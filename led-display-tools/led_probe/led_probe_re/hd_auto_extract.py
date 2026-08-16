#!/usr/bin/env python3
"""hd_auto_extract.py - pull the HD-Y1 auto-brightness RANGE block out of a USB
capture and save it as a <name>_auto.bin template.

The block is class 0x02 / sub 0x01 aimed at target 0x78 (the HD-Y1 multifunction
card); auto min% / max% live at payload offsets 457 / 458. HDset emits it when you
change the auto-brightness min/max on the auto-brightness screen and it's sent.

Self-contained: needs only **tshark** (Wireshark) - NO pyserial - so it runs on the
capture machine as-is. (This is the same extraction hd_bright.py --extract-auto-
template does, minus the pyserial import chain.)

    python hd_auto_extract.py wall2.pcapng                 # -> wall2_auto.bin
    python hd_auto_extract.py wall2.pcapng -o walls/wall2_auto.bin
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hd_bright_analyze as H          # noqa: E402  (tshark-only, no pyserial)

AUTO_CLASS, AUTO_SUB, AUTO_TARGET = 0x02, 0x01, 0x78
MIN_OFF, MAX_OFF = 457, 458
FRAME_LEN = 521


def main():
    ap = argparse.ArgumentParser(description="Extract the HD-Y1 auto-range block from a capture")
    ap.add_argument("pcap", help="capture of HDset changing auto min/max")
    ap.add_argument("-o", "--out", default=None, help="output .bin (default: <pcap>_auto.bin)")
    args = ap.parse_args()

    hs = [p for d, p in H.frames_for(args.pcap)
          if d == "H>D" and len(p) == FRAME_LEN
          and p[0] == AUTO_CLASS and p[1] == AUTO_SUB and p[3] == AUTO_TARGET]
    if not hs:   # relax the target filter in case it differs
        hs = [p for d, p in H.frames_for(args.pcap)
              if d == "H>D" and len(p) == FRAME_LEN and p[0] == AUTO_CLASS and p[1] == AUTO_SUB]
    if not hs:
        sys.exit("no class-0x02/sub-0x01 auto-range frame in this capture.\n"
                 "  Did HDset actually SEND an auto min/max change while capturing?\n"
                 "  Inspect what's there:  python hd_bright_analyze.py --dump " + args.pcap)

    out = args.out or (os.path.splitext(os.path.basename(args.pcap))[0] + "_auto.bin")
    with open(out, "wb") as f:
        f.write(hs[0])
    p = hs[0]
    print(f"wrote {out}: {len(p)}B  class0x{p[0]:02x}/sub0x{p[1]:02x}/tgt0x{p[3]:02x}  "
          f"min={p[MIN_OFF]}%  max={p[MAX_OFF]}%")
    if len(hs) > 1:
        print(f"  ({len(hs)} matching frames; used the first - they should be identical "
              f"but for min/max)")
    print("  next: diff it against another wall ->  python hd_auto_compare.py "
          "reference/example_wall1_auto.bin " + out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
