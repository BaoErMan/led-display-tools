#!/usr/bin/env python3
"""hd_auto_readback.py - read the HD-Y1's CURRENT auto-brightness min/max straight
off the card, with no HDset and no capture.

Why: an ACK to an auto-range write only proves the frame parsed. This polls the
multifunction card and reports what it actually holds, so "the write stuck" can be
checked directly.

How: the same query HDset uses on its auto-brightness screen -
    class 0x01 / sub 0x01 / target 0x78   ->   521-byte class-0x03 reply
The reply carries the configured min/max as an adjacent pair. Its position moves
between two known layouts depending on which command preceded the poll (see
PROTOCOL.md), so both are read and the plausible one reported:
    457/458  after a query 0x01/0x02/0x78
    469/470  after a brightness or auto-range write
Offset 15 is the live light reading, and 18 is the live auto OUTPUT (clamped to
min..max) - both are printed as context, and neither is the setting.

Needs pyserial + this wall's serial port. HDset must be CLOSED (its localserver
holds the port).

    python hd_auto_readback.py --port COM4
    python hd_auto_readback.py --port COM4 --expect 25,75
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hd_probe import build_frame, deframe, open_serial, DEFAULT_BAUD  # noqa: E402
from hd_bright import read_reply                                       # noqa: E402

QUERY = bytes([0x01, 0x01, 0x00, 0x78, 0x01, 0, 0, 0, 0x10]) + b"\x00" * 16
PAIR_OFFSETS = (469, 457)          # try the post-write layout first
LIGHT_OFF, OUTPUT_OFF = 15, 18


def plausible(lo, hi):
    return 0 <= lo <= hi <= 100


def main():
    ap = argparse.ArgumentParser(description="Read the HD-Y1 auto min/max off the card")
    default_port = "COM4" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--expect", default=None, metavar="MIN,MAX",
                    help="verify the card holds these, e.g. 25,75")
    ap.add_argument("--raw", action="store_true", help="dump the reply header")
    args = ap.parse_args()

    try:
        ser = open_serial(args.port, args.baud)
    except Exception as e:
        sys.exit(f"cannot open {args.port}: {e}\n"
                 f"  HDset (localserver) holds the port - close it first.")
    try:
        ser.reset_input_buffer()
        ser.write(build_frame(QUERY))
        ser.flush()
        blocks = [p for p, _ok in deframe(read_reply(ser)) if len(p) == 521 and p[0] == 0x03]
    finally:
        ser.close()

    if not blocks:
        sys.exit("no class-0x03 reply from the multifunction card.\n"
                 "  Is this an HD-Y1 wall, and is the card powered?")
    p = blocks[0]
    if args.raw:
        print("  reply head:", p[:24].hex())

    found = None
    for off in PAIR_OFFSETS:
        lo, hi = p[off], p[off + 1]
        mark = ""
        if plausible(lo, hi) and found is None:
            found, mark = (off, lo, hi), "   <- reading this as the setting"
        print(f"  offsets {off}/{off+1}: min={lo:3d} max={hi:3d}{mark}")

    print(f"\n  live light reading  (offset {LIGHT_OFF}): {p[LIGHT_OFF]}")
    print(f"  live auto OUTPUT    (offset {OUTPUT_OFF}): {p[OUTPUT_OFF]}%"
          f"   (clamped to min..max; NOT the setting)")

    if not found:
        print("\n  neither pair looked like a valid min<=max percent - the layout may "
              "have moved; run hd_bright_analyze.py --dump on a capture.")
        return 1
    _off, lo, hi = found
    print(f"\n  CARD HOLDS: min {lo}%  max {hi}%")
    if args.expect:
        try:
            emin, emax = (int(x) for x in args.expect.split(","))
        except ValueError:
            sys.exit("  --expect wants MIN,MAX e.g. 25,75")
        if (lo, hi) == (emin, emax):
            print(f"  MATCHES --expect {emin},{emax}  ->  the write STUCK.")
            return 0
        print(f"  DOES NOT match --expect {emin},{emax}  ->  the card ACKed but kept "
              f"its own values.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
