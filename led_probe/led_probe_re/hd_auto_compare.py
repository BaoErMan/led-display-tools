#!/usr/bin/env python3
"""hd_auto_compare.py - diff two (or more) HD-Y1 auto-range blocks to decide
whether ONE template can be reused across the fleet or each wall needs its own.

The whole question for killing the per-wall capture is: apart from the min/max you
set (offsets 457/458), how many bytes differ between walls?
  * none            -> the block is GENERIC: one template + patch min/max works
                       for every HD-Y1 wall. No per-wall capture ever.
  * a small handful -> those are the per-wall fields (card IDs / a checksum);
                       likely derivable, so still no capture.
  * lots            -> genuinely per-wall; capture stays.

Point it at auto blocks from DIFFERENT walls (the min/max may differ - that's fine,
it's excluded). Self-contained: standard library only.

    python hd_auto_compare.py reference/example_wall1_auto.bin wall2_auto.bin
    python hd_auto_compare.py wallA_auto.bin wallB_auto.bin wallC_auto.bin
"""
import os
import sys

FRAME_LEN = 521
MIN_OFF, MAX_OFF = 457, 458


def load(path):
    with open(path, "rb") as f:
        p = f.read()
    if len(p) != FRAME_LEN or p[0] != 0x02 or p[1] != 0x01 or p[3] != 0x78:
        sys.exit(f"{path}: not a 521-byte class-0x02/sub-0x01/target-0x78 auto block\n"
                 f"  (got {len(p)}B class 0x{p[0]:02x}/sub 0x{p[1]:02x}/tgt 0x{p[3]:02x}). "
                 f"Extract with hd_auto_extract.py.")
    return p


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: hd_auto_compare.py <wallA_auto.bin> <wallB_auto.bin> [wallC_auto.bin ...]\n"
                 "  give auto blocks from DIFFERENT walls.")
    paths = sys.argv[1:]
    blocks = [(os.path.basename(p), load(p)) for p in paths]
    print(f"== comparing {len(blocks)} auto block(s) ==")
    for name, b in blocks:
        print(f"  {name}: min={b[MIN_OFF]}%  max={b[MAX_OFF]}%")

    ref = blocks[0][1]
    diffs = set()
    for _name, b in blocks[1:]:
        diffs.update(i for i in range(FRAME_LEN) if b[i] != ref[i])
    other = sorted(diffs - {MIN_OFF, MAX_OFF})

    print(f"\n{len(diffs)} offset(s) differ; {len(other)} excluding min/max (457/458).")

    if not other:
        print("\nVERDICT: GENERIC ✔")
        print("  Apart from the min/max you set, the blocks are IDENTICAL. One auto")
        print("  template works for EVERY HD-Y1 wall - the client just patches 457/458.")
        print("  No per-wall capture needed. Send back any one _auto.bin to bundle as")
        print("  the fleet default.")
        return 0

    # group differing offsets into contiguous runs and show each wall's bytes
    runs, s, pv = [], None, None
    for i in other:
        if s is None:
            s = pv = i
        elif i == pv + 1:
            pv = i
        else:
            runs.append((s, pv)); s = pv = i
    if s is not None:
        runs.append((s, pv))

    print("\nWall-specific field(s) (offset range -> each wall's bytes):")
    for a, b in runs:
        vals = "   ".join(f"{name}:{blk[a:b+1].hex()}" for name, blk in blocks)
        print(f"  {a:3d}-{b:3d} ({b-a+1}B)   {vals}")

    n = len(other)
    if n <= 24:
        print(f"\nVERDICT: MOSTLY GENERIC ({n} wall-specific byte(s)).")
        print("  Probably card IDs/MACs or a checksum. Send me the diff above + one")
        print("  _auto.bin: if those bytes are derivable (from the probe's card list,")
        print("  geometry, or a CRC) I synthesize them per wall -> still NO capture.")
    else:
        print(f"\nVERDICT: PER-WALL ({n} bytes differ).")
        print("  Substantial wall-specific data; per-wall capture likely stays. Send")
        print("  the diff anyway - there may still be structure we can exploit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
