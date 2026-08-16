#!/usr/bin/env python3
"""hd_template_check.py - does this wall.bin actually belong to this wall?

A Huidu brightness template carries that wall's whole screen configuration (EDID,
timings, display geometry), so sending the wrong one reconfigures the screen. This
answers "is this the right file" two ways:

  --config <export>   DEFINITIVE, needs no hardware. Export a FRESH screen config
                      from that wall's HDset (.sss on newer HDset, .ssx on older,
                      or net_default_new.xml), and this diffs the block inside it
                      against wall.bin. If they differ only in the brightness
                      level and the auto flag - the two fields that legitimately
                      change - it is the same wall.

  --port COMx         Compares the wall's receiving cards against the fingerprint
                      recorded beside the template at commissioning
                      (wall.bin.wall.json, written by --save-fingerprint). Only
                      possible if that fingerprint exists.

Note the block's own geometry fields are NOT the receiving-card geometry, so a
template cannot be matched to a wall by probing alone - that is why the fingerprint
is recorded separately, and why --config is the stronger check.

    python hd_template_check.py walls/wall_north.bin --config fresh_export.sss
    python hd_template_check.py walls/wall_north.bin --port COM8
    python hd_template_check.py walls/wall_north.bin --against other_wall.bin
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hd_bright import (load_template, FRAME_LEN, PCT_OFFS, SCALED_OFFS,  # noqa: E402
                       AUTO_OFF, fingerprint_path)

# Fields that legitimately differ between two exports of the SAME wall: the
# brightness level (and its scaled companions) and the auto-brightness flag.
BENIGN = set(PCT_OFFS) | set(SCALED_OFFS) | {AUTO_OFF}


def classify(a, b):
    """(benign_offsets, structural_offsets) between two 521-byte blocks."""
    diff = [o for o in range(min(len(a), len(b))) if a[o] != b[o]]
    return [o for o in diff if o in BENIGN], [o for o in diff if o not in BENIGN]


def report_blocks(tpl, other, other_name):
    benign, structural = classify(tpl, other)
    print(f"  template level {tpl[PCT_OFFS[0]]}%  auto={tpl[AUTO_OFF]}")
    print(f"  {other_name} level {other[PCT_OFFS[0]]}%  auto={other[AUTO_OFF]}")
    print(f"\n  differing: {len(benign)} benign (level/auto), "
          f"{len(structural)} structural")
    if not structural:
        print("\n  SAME WALL ✔")
        print("    Only the brightness level and/or auto flag differ - exactly what")
        print("    changes between two exports of one wall. Safe to use.")
        return 0
    print("\n  DIFFERENT WALL (or the wall was reconfigured) ✘")
    print(f"    {len(structural)} byte(s) outside level/auto differ:")
    for o in structural[:24]:
        print(f"      offset {o:3d}: template={tpl[o]:3d}  {other_name}={other[o]:3d}")
    if len(structural) > 24:
        print(f"      … and {len(structural)-24} more")
    print("\n    Do NOT send this template to that wall. Re-provision from its own")
    print("    config:  provision_wall.py --port <PORT> --config <its export>")
    # A caveat worth stating: exports from different HDset VERSIONS of the same
    # wall can also differ in a few bytes, several of them set-vs-zero.
    zeroish = [o for o in structural if tpl[o] == 0 or other[o] == 0]
    if zeroish and len(zeroish) >= len(structural) // 2:
        print(f"\n    NOTE: {len(zeroish)} of those are zero on one side. That pattern")
        print("    also shows up between different HDset VERSIONS of the same wall")
        print("    (HDset not clearing its buffer), so if the export came from a")
        print("    different HDset than the template did, re-export from the same one")
        print("    before concluding they are different walls.")
    return 1


def main():
    ap = argparse.ArgumentParser(description="Check a Huidu template belongs to a wall")
    ap.add_argument("template", help="the wall.bin to check")
    ap.add_argument("--config", metavar="EXPORT",
                    help="a FRESH screen-config export from the wall (.sss/.ssx/xml)")
    ap.add_argument("--against", metavar="OTHER.bin",
                    help="compare directly against another template")
    ap.add_argument("--max-cards", type=int, default=64,
                    help="how far along the chain to probe (must match how the "
                         "fingerprint was recorded)")
    ap.add_argument("--gap", type=int, default=3,
                    help="stop probing after this many consecutive silent indices")
    ap.add_argument("--port", default=None,
                    help="probe the wall and compare its recorded fingerprint")
    args = ap.parse_args()

    try:
        tpl = load_template(args.template)
    except (OSError, ValueError) as e:
        sys.exit(f"template: {e}")
    print(f"== {os.path.basename(args.template)} ==")

    if args.config:
        from find_config import scan_file
        good, _raw = scan_file(args.config)
        if not good:
            sys.exit(f"no sending-card block in {args.config}\n"
                     f"  diagnose with: find_config.py --explain {args.config}")
        return report_blocks(tpl, good[0][3], os.path.basename(args.config))

    if args.against:
        return report_blocks(tpl, load_template(args.against),
                             os.path.basename(args.against))

    if args.port:
        import json
        fp = fingerprint_path(args.template)
        if not os.path.exists(fp):
            print(f"  no fingerprint recorded ({os.path.basename(fp)} missing).")
            print("  Record one on the wall this template belongs to:")
            print(f"    hd_bright.py --port {args.port} --template {args.template} "
                  f"--save-fingerprint")
            print("  Or check definitively with --config <a fresh export>.")
            return 1
        from hd_bright import open_serial, probe_fingerprint, DEFAULT_BAUD
        expected = json.load(open(fp, encoding="utf-8")).get("cards")
        ser = open_serial(args.port, DEFAULT_BAUD)
        try:
            actual = probe_fingerprint(ser, args.max_cards, args.gap)
        finally:
            ser.close()
        print(f"  fingerprint recorded : {expected}")
        print(f"  wall on {args.port:<12}: {actual}")
        if actual == expected:
            print("\n  SAME WALL ✔  (receiving cards match the recorded fingerprint)")
            return 0
        print("\n  DIFFERENT WALL ✘  - do NOT send this template.")
        return 1

    ap.error("give --config (best), --against, or --port")


if __name__ == "__main__":
    sys.exit(main())
