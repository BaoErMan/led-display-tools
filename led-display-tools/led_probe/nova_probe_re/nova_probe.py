#!/usr/bin/env python3
"""
nova_probe.py - Emulate NovaLCT's receiving-card *detection* over a NovaStar
sending card (CP210x USB-serial bridge). Reverse-engineered from a usb-sniffer
capture; see PROTOCOL.md.

Frame (both directions):
    [55 AA]=request / [AA 55]=reply | ack ser src dst dev port idx(2,LE)
    cmd reg(5) len(2,LE) | data… | checksum(2,LE)
    checksum = (0x5555 + sum(bytes[2:-2])) & 0xFFFF

This replays NovaLCT's detection reads and reports the sending-card ID and each
output port's receiving-card model/firmware string. NOTE: module geometry is not
read by a detection pass and is not reported (see PROTOCOL.md).

Usage:
    python nova_probe.py --port /dev/ttyUSB0
    python nova_probe.py --port COM5 --raw
"""
import argparse, os, sys, time

try:
    import serial, serial.tools.list_ports
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

# shared Huidu/NovaStar frame identifier (workspace root, parent of this dir)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from led_vendor import (vendor, identify, nova_cksum,            # noqa: E402
                        HUIDU_PREAMBLE, huidu_crc32)

REQ = b"\x55\xaa"
REP = b"\xaa\x55"
DEFAULT_BAUD = 115200
SRC_PC = 0xFE
NPORTS = 2          # sending-card output ports to scan
MAX_INDEX = 16      # safety ceiling per port


cksum = nova_cksum               # (0x5555 + sum(bytes[2:-2])) & 0xFFFF, LE
def add_ck(b):      return b + cksum(b)


class Seq:
    def __init__(self): self.n = 0x40
    def next(self):
        self.n = (self.n + 1) & 0xFF
        return self.n


def _frame(seq, dev, port, idx, cmd, reg5, length, data=b""):
    b = bytearray(REQ)
    b += bytes([0x00, seq, SRC_PC, 0x00, dev, port])
    b += int(idx).to_bytes(2, "little")
    b += bytes([cmd])
    b += bytes(reg5)
    b += int(length).to_bytes(2, "little")
    b += data
    return add_ck(bytes(b))


def build_read(seq, dev, port, idx, reg5, length):
    """reg5 = 5 register/selector bytes [11:16]; length = bytes to read (LE16)."""
    return _frame(seq, dev, port, idx, 0x00, reg5, length)


def build_write(seq, dev, port, idx, reg5, data):
    """data = payload bytes (length field = len(data))."""
    return _frame(seq, dev, port, idx, 0x01, reg5, len(data), data)


def parse_reply(buf):
    """Find AA55 reply frames in buf, checksum-validate, return list of dicts."""
    out = []
    i = 0
    while True:
        j = buf.find(REP, i)
        if j < 0:
            break
        if j + 18 > len(buf):
            break
        dlen = int.from_bytes(buf[j + 16:j + 18], "little")
        flen = 18 + dlen + 2
        if j + flen > len(buf):
            i = j + 2
            continue
        fr = buf[j:j + flen]
        if cksum(fr[:-2]) == fr[-2:]:
            out.append({"ser": fr[3], "dev": fr[6], "port": fr[7],
                        "idx": int.from_bytes(fr[8:10], "little"),
                        "data": fr[18:18 + dlen], "raw": fr})
            i = j + flen
        else:
            i = j + 2
    return out


def read_reply(ser, idle=0.4, timeout=2.0, silence=0.8):
    rx = bytearray(); t0 = time.time(); last = time.time()
    while time.time() - t0 < timeout:
        try:
            c = ser.read(4096)
        except serial.SerialException:
            time.sleep(0.05); c = b""      # transient USB hiccup; keep what we have
        if c:
            rx += c; last = time.time()
        elif rx and time.time() - last > idle:
            break
        elif not rx and time.time() - t0 > silence:
            break
    return bytes(rx)


# Retries for a lossy link. A 1 Mbps wall was seen dropping bytes on 256-byte
# replies: frames arrived partial and misaligned, failing their checksum, so
# POPULATED cards read as absent while empty slots (all-zero replies) parsed
# fine. One-byte reads were unaffected, which is why brightness read correctly
# while card scans found nothing.
# One retry, not two. It recovers the occasional corrupted reply, but on a link
# that is corrupt on EVERY read no number of retries helps - it only multiplies
# the time, and read_reply runs to its full 2.0s timeout when garbage keeps
# arriving. Fix the baud instead; this is only a cushion.
TRANSACT_RETRIES = 1


def transact(ser, frame, raw=False, retries=TRANSACT_RETRIES):
    """Send a frame and return the parsed replies.

    Retries ONLY when bytes came back but none parsed - the signature of a
    corrupted or partial read. A silent index (no bytes at all) is a genuinely
    absent card and is NOT retried, so scanning empty indices stays fast."""
    if raw:
        print(f"    -> {frame.hex()}")
    for attempt in range(retries + 1):
        ser.reset_input_buffer(); ser.reset_output_buffer()
        ser.write(frame); ser.flush()
        rx = read_reply(ser)
        reps = parse_reply(rx)
        if reps:
            if raw:
                for r in reps:
                    print(f"    <- {r['raw'].hex()}"
                          + (f"   (after {attempt} retr{'y' if attempt==1 else 'ies'})"
                             if attempt else ""))
            return reps
        if not rx:
            return []                      # silent: absent card, do not retry
        if raw:
            print(f"    <- (no valid frame, {len(rx)}B) {rx[:48].hex()}"
                  + ("  retrying…" if attempt < retries else "  giving up"))
    return []


def huidu_probe_frame():
    """Minimal Huidu 'Probe' frame (preamble + 25-B payload + CRC32 LE) used only
    to elicit a reply from a Huidu controller during --whoami."""
    p = bytearray(25)
    p[0] = 0x01; p[1] = 0x01; p[2] = 0x00; p[4] = 0x01; p[8] = 0x10
    return HUIDU_PREAMBLE + bytes(p) + huidu_crc32(bytes(p))


def whoami(ser):
    """Probe the link and report the controller family. Returns one of
    'novastar', 'huidu', 'unknown'. Sends only harmless read/probe frames."""
    # 1) ask as NovaStar (sending-card ID read) — a NovaStar card answers with a
    #    checksum-valid AA55 frame.
    for fr in parse_reply(_raw_exchange(ser, build_read(Seq().next(), 0x00, 0, 0, TX_ID, 8))):
        if identify(fr["raw"])[0] == "novastar":
            return "novastar"
    # 2) ask as Huidu — a Huidu card answers with frames carrying the 55…D5 preamble.
    rx = _raw_exchange(ser, huidu_probe_frame())
    if HUIDU_PREAMBLE in rx:
        return "huidu"
    return "unknown"


def _raw_exchange(ser, frame):
    ser.reset_input_buffer(); ser.reset_output_buffer()
    ser.write(frame); ser.flush()
    return read_reply(ser)


# register selectors (from PROTOCOL.md). idx = receiving-card index on the chain.
RX_BLOCK   = bytes([0x00, 0x00, 0x00, 0x00, 0x02])   # receiving-card config block (geometry)
RX_FW      = bytes([0x00, 0x00, 0x00, 0x00, 0x08])   # receiving-card firmware strings
TX_ID      = bytes([0x00, 0x16, 0x00, 0x00, 0x00])   # sending-card ID/serial
TX_NSSD    = bytes([0x00, 0x00, 0x00, 0x00, 0x05])   # sending-card info (NSSD)

# geometry within the RX_BLOCK data payload (uint16 LE)
GEO_W_OFF = 23
GEO_H_OFF = 25


def parse_geometry(data):
    """Return (w, h) from a fetched RX_BLOCK, or None if not populated."""
    if len(data) >= GEO_H_OFF + 2:
        w = int.from_bytes(data[GEO_W_OFF:GEO_W_OFF + 2], "little")
        h = int.from_bytes(data[GEO_H_OFF:GEO_H_OFF + 2], "little")
        if 0 < w <= 4096 and 0 < h <= 4096:
            return w, h
    return None


def ascii_strings(data, minlen=4):
    out, cur = [], []
    for x in data:
        if 32 <= x < 127:
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


def main():
    ap = argparse.ArgumentParser(description="Emulate NovaLCT card detection over the NovaStar serial link")
    default_port = "COM5" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--ports", type=int, default=NPORTS, help="sending-card output ports to scan")
    ap.add_argument("--whoami", action="store_true",
                    help="just identify the controller family (Huidu vs NovaStar) and exit")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    if sys.platform == "win32" and args.port.upper().startswith("COM"):
        args.port = f"\\\\.\\{args.port}"
    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.05, write_timeout=2.0)
    except serial.SerialException as e:
        ports = [p.device for p in serial.tools.list_ports.comports()]
        sys.exit(f"Cannot open {args.port}: {e}\n  Available: {', '.join(ports) or 'none'}")

    if args.whoami:
        fam = whoami(ser)
        ser.close()
        print(f"{args.port}: {fam} controller")
        return 0 if fam != "unknown" else 1

    print(f"== NovaStar detect on {args.port} @ {args.baud} 8N1 ==")
    res = scan_cards(ser, args.ports, raw=args.raw)
    ser.close()
    print_scan(res)
    return 0 if res["cards"] else 1


def scan_cards(ser, ports=NPORTS, raw=False):
    """Read the sending card + each output port's receiving card. Returns a dict:
       {sending_id, sending_info, cards:[{port,width,height,model}]}."""
    seq = Seq()
    out = {"sending_id": None, "sending_info": [], "cards": []}

    reps = transact(ser, build_read(seq.next(), 0x00, 0, 0, TX_ID, 8), raw)
    if reps:
        out["sending_id"] = reps[0]["data"].hex()
    reps = transact(ser, build_read(seq.next(), 0x00, 0, 0, TX_NSSD, 256), raw)
    if reps:
        out["sending_info"] = ascii_strings(reps[0]["data"])

    for port in range(ports):
        block = transact(ser, build_read(seq.next(), 0x01, port, 0, RX_BLOCK, 256), raw)
        data = block[0]["data"] if block else b""
        if not data.strip(b"\x00"):
            continue
        geo = parse_geometry(data)
        fw = transact(ser, build_read(seq.next(), 0x01, port, 0, RX_FW, 256), raw)
        ss = ascii_strings(fw[0]["data"]) if fw else []
        model = next((s for s in ss if "MRV" in s or "_FPGA" in s or "_MCU" in s), None)
        out["cards"].append({"port": port,
                             "width": geo[0] if geo else None,
                             "height": geo[1] if geo else None,
                             "model": model.strip() if model else None})
    return out


def print_scan(res):
    if res["sending_id"]:
        print(f"  sending card ID: {res['sending_id']}")
    else:
        print("  sending card: no reply (check port/baud/cable)")
    if res["sending_info"]:
        print(f"  sending card info: {' | '.join(res['sending_info'])}")
    for c in res["cards"]:
        line = f"  port {c['port']+1}: receiving card present"
        if c["width"] and c["height"]:
            line += f"  {c['width']}x{c['height']}"
        if c["model"]:
            line += f"  [{c['model']}]"
        print(line)
    print(f"== {len(res['cards'])} port(s) with receiving cards ==")


if __name__ == "__main__":
    sys.exit(main())
