#!/usr/bin/env python3
"""sensor_analyze.py - decode a standalone Huidu light sensor from a USB capture,
by correlating its byte stream against you blocking and unblocking it.

This is for the THIRD sensor type: the one on Huidu systems with **no
multifunction card**, hanging off its own USB-serial COM port. It does not speak
the Huidu LED protocol - no 55..D5 preamble, no CRC32 - so hd_bright_analyze.py
will (correctly) find nothing in these captures. This tool makes no assumption
about framing at all: it dumps the raw stream and finds whichever byte tracks the
light.

Handles both capture formats, auto-detected:
  * USBPcap / usbmon (usb.*)   <- RECOMMENDED here: software-only, no sniffer
  * ataradov usb-sniffer (usbll)
Requires tshark on PATH.

    python sensor_analyze.py --devices sensor.pcapng      # what's on the bus?
    python sensor_analyze.py --dump    sensor.pcapng      # timestamped raw stream
    python sensor_analyze.py --track   sensor.pcapng      # find the sensor byte
    python sensor_analyze.py --track sensor.pcapng --dev 3 --csv out.csv

Start with --devices, pick the sensor's address, then --track --dev N.
"""
import argparse
import os
import subprocess
import sys

# usbll PIDs
PID_OUT, PID_IN, PID_SETUP = 0xE1, 0x69, 0x2D
PID_DATA0, PID_DATA1 = 0xC3, 0x4B
PID_ACK = 0xD2
TOKEN_PIDS = (PID_OUT, PID_IN, PID_SETUP)
DATA_PIDS = (PID_DATA0, PID_DATA1)
HANDSHAKE_PIDS = (PID_ACK, 0x5A, 0x5E)


def _tshark(pcap, args):
    if not os.path.isfile(pcap):
        sys.exit(f"no such capture file: {pcap}")
    try:
        return subprocess.run(["tshark", "-r", pcap] + args,
                              capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("tshark not found on PATH - install Wireshark/tshark.")


def _hexbytes(s):
    s = (s or "").strip().replace(":", "").replace(" ", "")
    if not s or s == "<none>":
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def _f(s, d=0.0):
    try:
        return float(s)
    except (TypeError, ValueError):
        return d


def _i(s, d=None):
    s = (s or "").strip()
    if not s:
        return d
    try:
        return int(s, 0)
    except ValueError:
        return d


def detect_format(pcap):
    # NB: no -c here. `-c N` caps packets READ, not packets matched, so it would
    # only ever inspect the first frame - which in these captures is a syslog
    # record, not usbll - and silently misroute every capture to the USB path.
    r = _tshark(pcap, ["-Y", "usbll", "-T", "fields", "-e", "frame.number"])
    return "usbll" if r.stdout.strip() else "usb"


def read_transfers(pcap):
    """[(t, dev, ep, dir, data)] for every data-bearing transfer, any endpoint
    type. No protocol assumptions - this is a raw stream reader."""
    if detect_format(pcap) == "usbll":
        return _read_usbll(pcap)
    return _read_usb(pcap)


def _read_usb(pcap):
    r = _tshark(pcap, ["-Y", "usb.capdata", "-T", "fields",
                       "-e", "frame.time_relative", "-e", "usb.device_address",
                       "-e", "usb.endpoint_address", "-e", "usb.capdata"])
    out = []
    for ln in r.stdout.splitlines():
        f = ln.split("\t")
        f += [""] * (4 - len(f))
        raw = _hexbytes(f[3])
        if not raw:
            continue
        ep = _i(f[2], 0)
        out.append((_f(f[0]), _i(f[1]), ep & 0x7F,
                    "D>H" if (ep & 0x80) else "H>D", raw))
    return out


def _read_usbll(pcap):
    r = _tshark(pcap, ["-Y", "usbll", "-T", "fields",
                       "-e", "frame.time_relative", "-e", "usbll.pid",
                       "-e", "usbll.device_addr", "-e", "usbll.endp",
                       "-e", "usbll.data"])
    out, tok, pending = [], (None, None, None), None
    for ln in r.stdout.splitlines():
        f = ln.split("\t")
        f += [""] * (5 - len(f))
        t, pid, addr, endp, data = _f(f[0]), _i(f[1]), _i(f[2]), _i(f[3]), f[4]
        if pid is None:
            continue
        if pid in TOKEN_PIDS:
            tok = (addr, endp, "D>H" if pid == PID_IN else "H>D")
            pending = None
        elif pid in DATA_PIDS:
            pending = (t, tok[0], tok[1], tok[2], _hexbytes(data))
        elif pid in HANDSHAKE_PIDS:
            # only ACKed data is real; NAKed data is retransmitted verbatim
            if pending and pid == PID_ACK and pending[4]:
                out.append(pending)
            pending = None
    return out


def devices(pcap):
    tr = read_transfers(pcap)
    if not tr:
        print("no data-bearing transfers found - is this the right capture?")
        return
    agg = {}
    for t, dev, ep, dirn, raw in tr:
        k = (dev, ep, dirn)
        a = agg.setdefault(k, {"n": 0, "bytes": 0, "first": raw, "lens": set()})
        a["n"] += 1
        a["bytes"] += len(raw)
        a["lens"].add(len(raw))
    span = max(t for t, *_ in tr) - min(t for t, *_ in tr)
    print(f"== {os.path.basename(pcap)}: {len(tr)} transfers over {span:.1f}s ==")
    print("  dev  ep  dir   count    bytes  sizes      first payload")
    for (dev, ep, dirn), a in sorted(agg.items(), key=lambda kv: -kv[1]["n"]):
        sizes = ",".join(str(x) for x in sorted(a["lens"])[:4])
        print(f"  {dev:3}  {ep:2}  {dirn}  {a['n']:6}  {a['bytes']:7}  "
              f"{sizes:9}  {a['first'][:16].hex()}")
    print("\n  The sensor is usually a steady stream of small D>H transfers.")
    print("  Then:  sensor_analyze.py --track <pcap> --dev <N>")


def _ascii(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def dump(pcap, dev=None, limit=200):
    tr = [x for x in read_transfers(pcap) if dev is None or x[1] == dev]
    print(f"== {len(tr)} transfer(s){'' if dev is None else f' for device {dev}'} ==")
    for t, d, ep, dirn, raw in tr[:limit]:
        print(f"  {t:8.3f}s dev{d} ep{ep} {dirn} {len(raw):3d}B  "
              f"{raw[:24].hex():<48} {_ascii(raw[:24])}")
    if len(tr) > limit:
        print(f"  … {len(tr)-limit} more (use --limit)")


def _spark(vals):
    """Coarse ASCII sparkline - enough to see a step when the sensor is covered."""
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return "-" * len(vals)
    chars = " .:-=+*#%@"
    return "".join(chars[min(len(chars) - 1,
                             int((v - lo) / (hi - lo) * (len(chars) - 1)))]
                   for v in vals)


def track(pcap, dev=None, direction="D>H", csv=None, min_spread=8):
    """Treat each D>H transfer as one record and report the byte offsets that move
    over time. Blocking the sensor should make one offset step clearly."""
    tr = [x for x in read_transfers(pcap)
          if (dev is None or x[1] == dev) and x[3] == direction]
    if not tr:
        print(f"no {direction} transfers"
              f"{'' if dev is None else f' for device {dev}'} - try --devices")
        return
    lens = {}
    for _t, _d, _e, _dir, raw in tr:
        lens[len(raw)] = lens.get(len(raw), 0) + 1
    rec = max(lens, key=lens.get)
    recs = [(t, raw) for t, _d, _e, _dir, raw in tr if len(raw) == rec]
    print(f"== {len(tr)} {direction} transfers; most common size {rec}B "
          f"({len(recs)} of them) ==")
    if len(recs) < 3:
        print("  too few same-size records to correlate - capture for longer")
        return
    span = recs[-1][0] - recs[0][0]
    print(f"   spanning {span:.1f}s\n")

    moving = []
    for off in range(rec):
        vals = [r[off] for _t, r in recs]
        spread = max(vals) - min(vals)
        if spread:
            moving.append((spread, off, vals))
    if not moving:
        print("  NO byte changed. Either the sensor was not read during the")
        print("  capture, or its reading never changed - block it for several")
        print("  seconds mid-capture and make sure the polling app is running.")
        return

    moving.sort(reverse=True)
    print("  offsets that vary (largest swing first):")
    for spread, off, vals in moving[:12]:
        flag = "  <-- strong candidate" if spread >= min_spread else ""
        print(f"    off {off:3d}: min={min(vals):3d} max={max(vals):3d} "
              f"spread={spread:3d}{flag}")
        print(f"             {_spark(vals[:110])}")
    print("\n  The sensor byte is the one whose sparkline steps down while you")
    print("  covered it and back up when you uncovered it.")

    if csv:
        with open(csv, "w", encoding="utf-8") as f:
            f.write("t," + ",".join(f"b{o}" for o in range(rec)) + "\n")
            for t, r in recs:
                f.write(f"{t:.3f}," + ",".join(str(x) for x in r) + "\n")
        print(f"\n  wrote {csv} ({len(recs)} rows x {rec} byte columns)")


def main():
    ap = argparse.ArgumentParser(
        description="Decode a standalone Huidu light sensor from a USB capture")
    ap.add_argument("pcap")
    ap.add_argument("--devices", action="store_true", help="inventory the bus")
    ap.add_argument("--dump", action="store_true", help="timestamped raw stream")
    ap.add_argument("--track", action="store_true", help="find the sensor byte")
    ap.add_argument("--dev", type=int, default=None, help="USB device address")
    ap.add_argument("--dir", default="D>H", choices=["D>H", "H>D"])
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--csv", default=None, help="write the byte time-series to CSV")
    args = ap.parse_args()

    if args.devices:
        devices(args.pcap)
    elif args.dump:
        dump(args.pcap, args.dev, args.limit)
    elif args.track:
        track(args.pcap, args.dev, args.dir, args.csv)
    else:
        devices(args.pcap)
        print()
        track(args.pcap, args.dev, args.dir, args.csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
