#!/usr/bin/env python3
r"""
hd_probe.py - Emulate the HDset "Probe" action over a Huidu sending card.

Reverse-engineered from a USB capture (ataradov sniffer) of HDset's
Screen Configuration -> Probe. See protocol notes in README.md.

Hardware: CP210x USB-UART bridge (USB 10c4:ea60), 115200 8N1.

Wire format (both directions), Ethernet-style framing:
    55 55 55 55 55 55 55 D5  |  payload (N bytes)  |  CRC32(payload) LE
    \________ preamble ______/                        \_ zlib/Ethernet CRC32 _/

Probe sequence: host sends one sub=1 frame per card index (0..N-1), then one
sub=2 frame for index 0.  Each *present* card replies with an ACK frame
(payload[0]=0x01) followed by a CONFIG frame (payload[0]=0x03) containing its
full readback (width/height as uint16 BE at payload offset 37).  An *absent*
index returns only the ACK — no CONFIG — which is how presence is determined.

Usage:
    python3 hd_probe.py                        # default port: COM10 (Win) / /dev/ttyUSB0 (Linux)
    python3 hd_probe.py --port COM10           # Windows
    python3 hd_probe.py --port /dev/ttyUSB0   # Linux
    python3 hd_probe.py --cards 4             # probe 4 card slots (default)
    python3 hd_probe.py --autodetect           # try a list of bauds, keep the working one
    python3 hd_probe.py --raw                  # also dump raw payload hex of every frame
"""

import argparse
import os
import sys
import time
import zlib

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial is required:  pip install pyserial")

# shared Huidu/NovaStar frame identifier (workspace root, parent of this dir)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from led_vendor import vendor, identify  # noqa: E402

PREAMBLE = bytes.fromhex("55555555555555d5")
DEFAULT_BAUD = 115200
AUTODETECT_BAUDS = [115200, 256000, 230400, 921600, 460800, 57600, 38400, 9600]

DEFAULT_CARD_COUNT = 4


def make_probe_sequence(n_cards):
    """sub=1 probe for each card index, then sub=2 for index 0 (mirrors HDset)."""
    return [make_probe_payload(i, sub=1) for i in range(n_cards)] + \
           [make_probe_payload(0, sub=2)]

CFG_GEOMETRY_OFFSET = 37  # uint16 BE width, uint16 BE height


# --------------------------------------------------------------------------- #
# Framing helpers
# --------------------------------------------------------------------------- #
def crc32le(payload: bytes) -> bytes:
    """Standard CRC32 (Ethernet/zlib), appended little-endian."""
    return (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little")


def build_frame(payload: bytes) -> bytes:
    """preamble + payload + CRC32(payload) little-endian."""
    return PREAMBLE + payload + crc32le(payload)


def make_probe_payload(index: int, sub: int = 1) -> bytes:
    """Build a probe query payload for a given card index / sub-command."""
    body = bytearray(25)
    body[0] = 0x01          # command class
    body[1] = sub & 0xFF    # sub-command (1 = scan, 2 = follow-up)
    body[2] = index & 0xFF  # receiving-card index
    body[4] = 0x01          # observed constant (count = 1)
    body[8] = 0x10          # observed constant (0x10)
    return bytes(body)


def deframe(stream: bytes):
    """
    Scan a byte stream for valid frames. Frames have no length field, so for
    each preamble we look for the next preamble (or end of stream) and then
    walk back to find an end offset whose trailing 4 bytes are a valid CRC32
    of the payload in between. Yields (payload, crc_ok=True) for each frame.
    """
    frames = []
    # positions of every preamble
    starts = []
    i = 0
    while True:
        j = stream.find(PREAMBLE, i)
        if j < 0:
            break
        starts.append(j)
        i = j + 1
    starts.append(len(stream))  # sentinel end

    for k in range(len(starts) - 1):
        seg = stream[starts[k]:starts[k + 1]]
        body_and_crc = seg[len(PREAMBLE):]
        # The true frame may be shorter than the segment if trailing junk/idle
        # bytes follow. Try the longest CRC-valid prefix.
        best = None
        # need at least 1 payload byte + 4 CRC
        for end in range(len(body_and_crc), 4, -1):
            payload = body_and_crc[: end - 4]
            crc = body_and_crc[end - 4: end]
            if crc32le(payload) == crc:
                best = payload
                break
        if best is not None:
            frames.append((best, True))
    return frames


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_config(payload: bytes) -> dict:
    """Decode a CONFIG frame (payload[0]==0x03)."""
    index = payload[2] if len(payload) > 2 else None
    width = height = None
    if len(payload) >= CFG_GEOMETRY_OFFSET + 4:
        o = CFG_GEOMETRY_OFFSET
        width = int.from_bytes(payload[o:o + 2], "big")
        height = int.from_bytes(payload[o + 2:o + 4], "big")
    return {"index": index, "width": width, "height": height,
            "len": len(payload), "raw": payload.hex()}


# --------------------------------------------------------------------------- #
# Serial exchange
# --------------------------------------------------------------------------- #
def _read_reply(ser, idle=0.25, timeout=1.5):
    """Read from the port until it stays idle for `idle` s (or `timeout`)."""
    rx = bytearray()
    deadline = time.time() + timeout
    last_rx = time.time()
    while time.time() < deadline:
        chunk = ser.read(4096)
        if chunk:
            rx += chunk
            last_rx = time.time()
        elif rx and time.time() - last_rx > idle:
            break
    return bytes(rx)


def run_probe(ser, n_cards=DEFAULT_CARD_COUNT):
    """
    Send each probe frame and drain its reply before the next one, mirroring
    HDset (which waits for each card's response before querying the next index).
    Sending all frames at once overruns the card and loses replies.
    """
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    rx = bytearray()
    for payload in make_probe_sequence(n_cards):
        ser.write(build_frame(payload))
        ser.flush()
        rx += _read_reply(ser)
    return bytes(rx)


def summarize(rx: bytes, n_cards: int, raw=False) -> int:
    frames = deframe(rx)
    acks = [p for p, _ in frames if p and p[0] == 0x01]
    cfgs = [parse_config(p) for p, _ in frames if p and p[0] == 0x03]
    cfg_by_index = {c['index']: c for c in cfgs}

    print(f"Received {len(rx)} bytes -> {len(frames)} valid frames "
          f"({len(acks)} ACK, {len(cfgs)} config)")
    if raw:
        for p, _ in frames:
            print(f"  frame[{p[0]:02x} idx={p[2] if len(p)>2 else '?'}] "
                  f"{len(p)}B  {p.hex()}")

    print(f"\nProbed {n_cards} card slot(s):")
    for i in range(n_cards):
        if i in cfg_by_index:
            c = cfg_by_index[i]
            print(f"  slot {i}: PRESENT  {c['width']} x {c['height']}  "
                  f"(config {c['len']} B)")
        else:
            print(f"  slot {i}: absent")
    return len(cfgs)


def open_serial(port, baud):
    # Pyserial only prefixes \\.\  for COM10+; force it for all COM ports so
    # Windows resolves the device path correctly regardless of port number.
    if sys.platform == "win32" and port.upper().startswith("COM"):
        port = f"\\\\.\\{port}"
    return serial.Serial(port=port, baudrate=baud, bytesize=serial.EIGHTBITS,
                         parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                         timeout=0.1, write_timeout=2.0)


def main():
    ap = argparse.ArgumentParser(description="Emulate HDset Probe over the Huidu serial link")
    default_port = "COM10" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--cards", type=int, default=DEFAULT_CARD_COUNT,
                    help=f"number of receiving cards to probe (default {DEFAULT_CARD_COUNT})")
    ap.add_argument("--autodetect", action="store_true",
                    help="try several bauds, keep the first that returns valid frames")
    ap.add_argument("--raw", action="store_true", help="dump raw payload hex of every frame")
    args = ap.parse_args()

    bauds = ([args.baud] + [b for b in AUTODETECT_BAUDS if b != args.baud]) \
        if args.autodetect else [args.baud]

    for baud in bauds:
        try:
            ser = open_serial(args.port, baud)
        except serial.SerialException as e:
            ports = [p.device for p in serial.tools.list_ports.comports()]
            hint = f"  Available ports: {', '.join(ports)}" if ports else "  No serial ports detected."
            sys.exit(f"Cannot open {args.port}: {e}\n{hint}")
        print(f"== Probing on {args.port} @ {baud} 8N1, {args.cards} card(s) ==")
        try:
            rx = run_probe(ser, n_cards=args.cards)
        finally:
            ser.close()
        n = summarize(rx, n_cards=args.cards, raw=args.raw)
        if n > 0 or not args.autodetect:
            return 0 if n > 0 else 1
        print("  (no cards at this baud, trying next)\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
