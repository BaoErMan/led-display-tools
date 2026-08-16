#!/usr/bin/env python3
"""
extract.py - Pull the NovaStar serial frames out of an ataradov usb-sniffer
capture of NovaLCT's receiving-card scan.

The capture is USB link-layer (usbll). We only care about the CP210x bulk pipe;
its (device address, endpoint) is auto-detected because the CP210x re-enumerates
at a different address each time it is re-attached. Endpoint 0 is CP210x
control-status polling and is dropped. Direction comes from the token (IN/OUT)
preceding each DATA packet, NOT from the AA55/55AA start code.

Usage: python extract.py [capture.pcap]   (default: probe.pcap)

Full-speed bulk max packet = 64 B, so a transfer larger than 64 B is split into
64-B DATA packets; we reassemble a transfer by concatenating consecutive
same-direction DATA packets until a short (<64 B) packet ends it.

Output:
    all_data.tsv   frame#   dir(H>D / D>H)   hex
    (one row per reassembled bulk transfer; control + empty/NAK noise removed)
"""
import subprocess, sys, os

PCAP = os.path.join(os.path.dirname(__file__), "probe.pcap")
MAXPKT = 64
# bulk pipe (device address, endpoint) — auto-detected per capture; the CP210x
# re-enumerates at a different address each time it is re-attached.
BULK_EP = None
DEV_ADDR = None

# usbll PID bytes
PID_OUT, PID_IN, PID_SETUP = 0xE1, 0x69, 0x2D
PID_DATA0, PID_DATA1 = 0xC3, 0x4B
DATA_PIDS = (PID_DATA0, PID_DATA1)
TOKEN_PIDS = (PID_OUT, PID_IN, PID_SETUP)


def read_events(pcap):
    """Yield (frame_no, pid, endp, datahex) for token+data packets in order."""
    cmd = ["tshark", "-r", pcap, "-Y",
           "usbll.pid==0xe1 || usbll.pid==0x69 || usbll.pid==0x2d || "
           "usbll.pid==0xc3 || usbll.pid==0x4b",
           "-T", "fields", "-e", "frame.number", "-e", "usbll.pid",
           "-e", "usbll.device_addr", "-e", "usbll.endp", "-e", "usbll.data"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in p.stdout:
        f = line.rstrip("\n").split("\t")
        if len(f) < 5:
            f += [""] * (5 - len(f))
        frame, pid, addr, endp, data = f
        try:
            pid = int(pid, 16)
        except ValueError:
            continue
        addr = int(addr) if addr else None
        endp = int(endp) if endp else None
        yield int(frame), pid, addr, endp, data
    p.wait()


def detect_bulk_pipe(pcap):
    """The bulk pipe = the (device_addr, endpoint!=0) carrying the most IN/OUT
    tokens. Endpoint 0 is CP210x control and is excluded."""
    counts = {}
    for _, pid, addr, endp, _ in read_events(pcap):
        if pid in (PID_IN, PID_OUT) and endp not in (None, 0) and addr is not None:
            counts[(addr, endp)] = counts.get((addr, endp), 0) + 1
    if not counts:
        return None, None
    (addr, endp), _ = max(counts.items(), key=lambda kv: kv[1])
    return addr, endp


def reassemble(pcap):
    """Walk the stream, attach each DATA packet to the last token's direction,
    and merge consecutive same-direction DATA packets into transfers."""
    global DEV_ADDR, BULK_EP
    if DEV_ADDR is None:
        DEV_ADDR, BULK_EP = detect_bulk_pipe(pcap)
        print(f"  bulk pipe: device {DEV_ADDR} endpoint {BULK_EP}")
    transfers = []          # (frame_no, "H>D"|"D>H", bytes)
    cur_dir = None          # direction of the open transfer
    cur_buf = bytearray()
    cur_frame = None
    # context from the most recent token (DATA packets don't carry addr/endp)
    tok_addr = tok_endp = tok_dir = None

    def flush():
        nonlocal cur_buf, cur_dir, cur_frame
        if cur_buf:
            transfers.append((cur_frame, cur_dir, bytes(cur_buf)))
        cur_buf = bytearray()
        cur_dir = None
        cur_frame = None

    for frame, pid, addr, endp, data in read_events(pcap):
        if pid in TOKEN_PIDS:
            tok_addr, tok_endp = addr, endp
            tok_dir = "D>H" if pid == PID_IN else "H>D"  # SETUP grouped as H>D
            continue
        if pid in DATA_PIDS:
            # this DATA belongs to the pipe addressed by the preceding token.
            # Ignore non-bulk pipes (e.g. CP210x control polling) WITHOUT
            # flushing — they routinely interleave a multi-packet bulk reply.
            if tok_addr != DEV_ADDR or tok_endp != BULK_EP:
                continue
            raw = bytes.fromhex(data) if data and data != "<none>" else b""
            if tok_dir != cur_dir:
                flush()
                cur_dir = tok_dir
                cur_frame = frame
            if cur_frame is None:
                cur_frame = frame
            cur_buf += raw
            # NB: do NOT end on a short USB packet. A single logical NovaStar
            # reply is delivered as several short bulk transfers; we concatenate
            # the whole same-direction burst and let the frame parser split it
            # using the length field. Flush only when the direction flips.
    flush()
    # drop empty/1-byte handshake transfers
    return [(f, d, b) for (f, d, b) in transfers if len(b) >= 2]


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else PCAP
    xfers = reassemble(pcap)
    out = os.path.join(os.path.dirname(pcap), "all_data.tsv")
    with open(out, "w") as fh:
        for frame, d, b in xfers:
            fh.write(f"{frame}\t{d}\t{b.hex()}\n")
    print(f"{len(xfers)} transfers -> {out}")
    # quick summary
    h2d = [x for x in xfers if x[1] == "H>D"]
    d2h = [x for x in xfers if x[1] == "D>H"]
    print(f"  host->device (commands): {len(h2d)}")
    print(f"  device->host (replies):  {len(d2h)}")


if __name__ == "__main__":
    main()
