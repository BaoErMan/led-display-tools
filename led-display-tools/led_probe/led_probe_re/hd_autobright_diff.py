#!/usr/bin/env python3
"""hd_autobright_diff.py - re-derive where the HD-Y1 auto-brightness MIN/MAX %
live, by diffing two HDset exports taken at different auto-brightness settings.

    ALREADY ANSWERED - you probably do not need this tool.
    min/max are at payload offsets 457 / 458 of the class-0x02 / sub-0x01 block
    aimed at target 0x78 (the multifunction card). Confirmed across three
    captures. Use hd_bright.py --auto-min/--auto-max, or
    HdLink.set_auto_range(). Keep this only to re-derive the offsets if a
    different firmware moves them.

    Two things this tool CANNOT do, both verified:
      * it searches the SENDING-CARD block (sub 0x00), where 457/458 are display
        geometry - the auto range is not in that block at all;
      * HDset does not store the multifunction block in its config, so diffing
        two config exports will never show the auto range changing. A USB
        capture of the auto-brightness screen is the only source.

Background
----------
An HD-Y1 in ambient mode runs the brightness loop in HARDWARE, clamped to a
configured min% / max%. Our brightness command patches the MANUAL level bytes,
which the card ignores while auto is on - so to steer HD-Y1 ambient brightness
from the dashboard we must write those min/max fields, and we do not yet know
where they are in the 521-byte block. This tool locates them.

What to capture (no USB sniffer needed if HDset saves its config)
-----------------------------------------------------------------
In HDset, on the auto-brightness screen, change ONLY the min/max and export the
config each time (keep the manual level and the auto flag the same, to keep the
diff clean):

    1. set auto min=10, max=80  -> save/export the config     -> A.xml
    2. set auto min=30, max=60  -> save/export the config     -> B.xml

"export" = HDset's saved config file, normally
    <HDset>/public/recvfile/net_default_new.xml
Copy it aside after each change. (A captured class-0x02 .bin frame from each
setting works too - the tool auto-detects raw 521-byte blocks vs XML exports.)

Run
---
    python hd_autobright_diff.py A.xml B.xml --a-min 10 --a-max 80 --b-min 30 --b-max 60

The percentages are optional but let it pinpoint the fields by value; without them
it just prints every byte that changed. It reports the LIKELY min/max offsets, or -
if the two blocks are identical - that the setting is NOT in this block and a
capture of HDset's auto-brightness screen is the next step.

Self-contained: standard library only. No pyserial, no hardware.
"""
import argparse
import base64
import re
import sys

# --- block layout (mirrors hd_bright.py, inlined so this needs no serial) ---- #
FRAME_LEN = 521
HEADER_LEN = 9
AUTO_OFF = 22                       # 0=manual, 1=auto
PCT_OFFS = (58, 60, 62, 64)         # manual level, direct 0-100 percent
SCALED_OFFS = (59, 61, 63, 65)      # manual level, pct*128//100
SIG_OFF = 57                        # 0xff marker just before the level pairs
CANON_HEADER = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00])

KNOWN = {AUTO_OFF: "auto-flag"}
for _o in PCT_OFFS:
    KNOWN[_o] = "manual-level"
for _o in SCALED_OFFS:
    KNOWN[_o] = "manual-level-scaled"


def pct_to_scaled(pct):
    return max(0, min(128, int(pct) * 128 // 100))


def is_brightness_block(p):
    """The sending-card block signature: 0xff at 57, then four identical
    (percent, percent*128//100) pairs at PCT_OFFS/SCALED_OFFS."""
    if len(p) != FRAME_LEN or p[SIG_OFF] != 0xFF:
        return False
    pcts = [p[o] for o in PCT_OFFS]
    if len(set(pcts)) != 1 or not 0 <= pcts[0] <= 100:
        return False
    return all(p[o] == pct_to_scaled(pcts[0]) for o in SCALED_OFFS)


# --- pull the 521-byte block out of a file (raw .bin or HDset XML export) ---- #
B64_RE = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")


def _decoded_layers(data, depth=2):
    """Yield base64 payloads nested inside `data` (HDset buries the block two
    base64 layers down inside net_default_new.xml)."""
    if depth < 0:
        return
    for m in B64_RE.finditer(data):
        s = m.group(0)
        try:
            dec = base64.b64decode(s + b"=" * (-len(s) % 4))
        except Exception:
            continue
        if len(dec) < FRAME_LEN - HEADER_LEN:
            continue
        yield dec
        yield from _decoded_layers(dec, depth - 1)


def _find_block_in(blob):
    """Return the first 521-byte brightness block in `blob`, trying both layouts:
    the blob holds the full payload, or only the 512-byte data area (add header).
    Anchored on the 0xff marker so the scan is cheap."""
    start = 0
    while True:
        i = blob.find(b"\xff", start)
        if i < 0:
            return None
        start = i + 1
        # (a) full payload: 0xff sits at offset SIG_OFF
        s = i - SIG_OFF
        if 0 <= s and s + FRAME_LEN <= len(blob):
            cand = bytes(blob[s:s + FRAME_LEN])
            if is_brightness_block(cand):
                return cand
        # (b) data-area only: prepend the canonical 9-byte header
        sd = i - (SIG_OFF - HEADER_LEN)
        if 0 <= sd and sd + (FRAME_LEN - HEADER_LEN) <= len(blob):
            cand = CANON_HEADER + bytes(blob[sd:sd + FRAME_LEN - HEADER_LEN])
            if is_brightness_block(cand):
                return cand


def extract_block(path):
    """Get the 521-byte block from a raw frame file or an HDset XML export."""
    with open(path, "rb") as f:
        data = f.read()
    # raw .bin: the file IS the block (or the block is somewhere in it)
    if len(data) == FRAME_LEN and is_brightness_block(data):
        return data
    b = _find_block_in(data)
    if b is not None:
        return b
    for layer in _decoded_layers(data):
        b = _find_block_in(layer)
        if b is not None:
            return b
    return None


# --- diff + identify --------------------------------------------------------- #
def diff_blocks(a, b):
    return [(o, a[o], b[o]) for o in range(FRAME_LEN) if a[o] != b[o]]


def value_matches(diffs, a_val, b_val):
    """Offsets whose (A,B) equal a given (a_val, b_val), direct or *128/100."""
    direct = [o for o, av, bv in diffs if av == a_val and bv == b_val]
    scaled = [o for o, av, bv in diffs
              if av == pct_to_scaled(a_val) and bv == pct_to_scaled(b_val)]
    return direct, scaled


def main():
    ap = argparse.ArgumentParser(
        description="Locate HD-Y1 auto-brightness min/max offsets by diffing two "
                    "HDset config exports",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", metavar="A", help="first export (min=A-MIN, max=A-MAX)")
    ap.add_argument("b", metavar="B", help="second export (min=B-MIN, max=B-MAX)")
    ap.add_argument("--a-min", type=int, help="auto MIN %% set when A was saved")
    ap.add_argument("--a-max", type=int, help="auto MAX %% set when A was saved")
    ap.add_argument("--b-min", type=int, help="auto MIN %% set when B was saved")
    ap.add_argument("--b-max", type=int, help="auto MAX %% set when B was saved")
    args = ap.parse_args()

    blocks = {}
    for tag, path in (("A", args.a), ("B", args.b)):
        blk = extract_block(path)
        if blk is None:
            sys.exit(f"{path}: no sending-card brightness block found.\n"
                     f"  Point at an HDset config export (net_default_new.xml) or a\n"
                     f"  captured class-0x02 frame. Run find_config.py --explain on it\n"
                     f"  to see why the block was not located.")
        blocks[tag] = blk
        print(f"  {tag}: block from {path}  "
              f"(manual level={blk[PCT_OFFS[0]]}%, auto={blk[AUTO_OFF]})")

    diffs = diff_blocks(blocks["A"], blocks["B"])
    print(f"\n== {len(diffs)} byte(s) differ between the two blocks ==")

    if not diffs:
        print("  The two blocks are IDENTICAL. The HD-Y1 auto min/max is NOT stored")
        print("  in this sending-card block - it lives in the multifunction-card")
        print("  (HD-Y1) config. Next step: capture HDset's auto-brightness screen")
        print("  with the USB sniffer while changing min/max, then decode that")
        print("  command (hd_bright_analyze.py --writes on the capture).")
        return 2

    # full table, annotating fields we already know so they aren't mistaken for min/max
    print("  offset   A    B    note")
    for o, av, bv in diffs:
        note = KNOWN.get(o, "")
        print(f"   {o:4d}   {av:3d}  {bv:3d}   {note}")

    have_pcts = all(v is not None for v in (args.a_min, args.a_max, args.b_min, args.b_max))
    if not have_pcts:
        print("\n  Pass --a-min/--a-max/--b-min/--b-max (the %% you set in HDset) to")
        print("  pinpoint the min/max fields by value.")
        return 0

    print(f"\n== matching against min {args.a_min}->{args.b_min}, "
          f"max {args.a_max}->{args.b_max} ==")
    found = []
    for label, av, bv in (("auto MIN", args.a_min, args.b_min),
                          ("auto MAX", args.a_max, args.b_max)):
        direct, scaled = value_matches(diffs, av, bv)
        direct = [o for o in direct if o not in KNOWN]
        scaled = [o for o in scaled if o not in KNOWN]
        if direct:
            print(f"  {label}: offset(s) {direct}  (direct 0-100%)")
            found += [(label, o, "direct") for o in direct]
        if scaled:
            print(f"  {label}: offset(s) {scaled}  (scaled *128/100 companion)")
            found += [(label, o, "scaled") for o in scaled]
        if not direct and not scaled:
            print(f"  {label}: no byte changed exactly {av}->{bv} - it may be stored "
                  f"differently, or A/B were not set as expected")

    if found:
        print("\n  LIKELY the fields to patch (mirror the manual-level patch in")
        print("  hd_bright.build_brightness_payload, then expose as HD-Y1 min/max")
        print("  sliders on the dashboard). VERIFY on hardware before trusting.")
    else:
        print("\n  No confident match. Re-export making sure ONLY min/max changed")
        print("  between A and B (same manual level, same auto flag).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
