#!/usr/bin/env python3
"""hd_scan.py - find the Huidu READ command that returns the sending-card
parameters block, so a fleet client can acquire its brightness template from the
hardware instead of from a USB capture.

Why this exists
---------------
Setting brightness means replaying the 521-byte class-0x02 "sending card
parameters" block with the level patched in (PROTOCOL.md). That block is
wall-specific, and so far the only way to obtain it is to sniff HDset pressing
Send - which needs a USB sniffer on site and is hopeless for fleet rollout.

Neither read command we know returns it:
    class 0x01 sub 0x01 target 0x00 -> receiving-card config   (no EDID)
    class 0x01 sub 0x01 target 0x78 -> multifunction config    (no EDID)
The write block *does* carry the EDID and the brightness bytes, so some other
(sub, target) query should read it back. This sweeps for it.

SAFETY
------
This tool sends **class 0x01 only**. Every class-0x01 frame observed in every
capture is a query, and every write has been class 0x02. Nothing here writes to
the wall. Do NOT extend this to class 0x02 to "see what happens" - that class
carries whole config blocks and a malformed one would reconfigure the screen.

    python hd_scan.py --port COM8                     # curated sweep
    python hd_scan.py --port COM8 --targets 0-255     # exhaustive, sub 1
    python hd_scan.py --port COM8 --save-template     # save the block if found
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hd_probe import build_frame, deframe, open_serial, DEFAULT_BAUD  # noqa: E402
from hd_bright import (read_reply, DEFAULT_TEMPLATE, FRAME_LEN,       # noqa: E402
                       PCT_OFFS, SCALED_OFFS, AUTO_OFF, pct_to_scaled)

QUERY_CLASS = 0x01          # the ONLY class this tool ever sends
EDID_MAGIC = bytes.fromhex("00ffffffffffff00")


def build_query(sub, target, idx=0):
    """`01 <sub> <idx> <target> 01 00 00 00 10` + 16 zero bytes.

    Matches every observed query byte-for-byte:
        01 01 00 00 ... receiving-card probe
        01 01 00 78 ... multifunction poll
        01 02 00 78 ... the second multifunction query
    """
    return bytes([QUERY_CLASS, sub, idx, target, 0x01, 0, 0, 0, 0x10]) + b"\x00" * 16


def looks_like_brightness_block(p):
    """True if `p` has the sending-card block's brightness signature: 0xff at 57
    then four identical (percent, percent*128//100) pairs. Strong enough to
    identify the block without knowing the wall's current level."""
    if len(p) != FRAME_LEN or p[57] != 0xFF:
        return False
    pcts = [p[o] for o in PCT_OFFS]
    if len(set(pcts)) != 1 or not 0 <= pcts[0] <= 100:
        return False
    return all(p[o] == pct_to_scaled(pcts[0]) for o in SCALED_OFFS)


def describe(p):
    """One-line fingerprint of a reply block."""
    bits = [f"class=0x{p[0]:02x}", f"len={len(p)}"]
    if EDID_MAGIC in p:
        bits.append("EDID")
    if b"HD " in p:
        bits.append("model-string")
    if looks_like_brightness_block(p):
        bits.append(f"** BRIGHTNESS BLOCK (level={p[PCT_OFFS[0]]}%, "
                    f"auto={p[AUTO_OFF]}) **")
    return "  ".join(bits)


def query(ser, sub, target, idx=0, settle=0.15):
    """Send one query, return the CRC-valid reply payloads."""
    ser.reset_input_buffer()
    ser.write(build_frame(build_query(sub, target, idx)))
    ser.flush()
    time.sleep(settle)
    return [fp for fp, _ok in deframe(read_reply(ser))]


def parse_range(s):
    out = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a, 0), int(b, 0) + 1))
        else:
            out.append(int(part, 0))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Sweep Huidu READ queries for the sending-card block (read-only)")
    default_port = "COM10" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--subs", default="0-3", help="sub-commands to try (default 0-3)")
    ap.add_argument("--targets", default="0x00,0x01,0x02,0x0f,0x10,0x78,0x80,0xe8,0xf0,0xff",
                    help="target bytes to try; use 0-255 for an exhaustive sweep")
    ap.add_argument("--save-template", nargs="?", const=DEFAULT_TEMPLATE, default=None,
                    metavar="PATH",
                    help="if the brightness block is found, save it as a template")
    ap.add_argument("--all", action="store_true",
                    help="shorthand for --targets 0-255 --subs 0-15")
    ap.add_argument("--save-blocks", metavar="DIR", default=None,
                    help="write every distinct 521-byte reply block to DIR for "
                         "offline analysis")
    ap.add_argument("--quiet", action="store_true",
                    help="only print distinct reply signatures, not every query")
    args = ap.parse_args()

    subs = parse_range("0-15" if args.all else args.subs)
    targets = parse_range("0-255" if args.all else args.targets)

    try:
        ser = open_serial(args.port, args.baud)
    except Exception as e:
        sys.exit(f"Cannot open {args.port}: {e}\n  HDset holds the port - close it first.")

    print(f"== scanning {len(subs)}x{len(targets)} class-0x01 queries on {args.port} ==")
    print("   (read-only: this tool never sends class 0x02)\n")
    found = None
    hits = 0
    sigs = {}          # reply signature -> [(sub,target), ...]
    blocks_seen = {}   # block bytes -> (sub,target)
    try:
        for sub in subs:
            for tgt in targets:
                reps = query(ser, sub, tgt)
                if not reps:
                    continue
                hits += 1
                sig = " | ".join(describe(p) for p in reps)
                sigs.setdefault(sig, []).append((sub, tgt))
                if not args.quiet:
                    print(f"  sub=0x{sub:02x} target=0x{tgt:02x} -> {sig}")
                for p in reps:
                    if len(p) == FRAME_LEN:
                        blocks_seen.setdefault(bytes(p), (sub, tgt))
                    if found is None and looks_like_brightness_block(p):
                        found = (sub, tgt, p)
    except KeyboardInterrupt:
        print("\n  interrupted")
    finally:
        ser.close()

    # The useful part: what actually came back, collapsed.
    print(f"\n== {hits} query/queries answered; "
          f"{len(sigs)} distinct reply signature(s) ==")
    for sig, where in sorted(sigs.items(), key=lambda kv: -len(kv[1])):
        first = ", ".join(f"(sub 0x{s:02x}, tgt 0x{t:02x})" for s, t in where[:4])
        more = f" … +{len(where)-4} more" if len(where) > 4 else ""
        print(f"  {len(where):4d}x  {sig}")
        print(f"        from {first}{more}")
    print(f"\n== {len(blocks_seen)} distinct 521-byte block(s) seen ==")
    for i, (blk, (s, t)) in enumerate(blocks_seen.items()):
        print(f"  block {i}: sub=0x{s:02x} target=0x{t:02x}  class=0x{blk[0]:02x}  "
              f"EDID={EDID_MAGIC in blk}  head={blk[:12].hex()}")
        if args.save_blocks:
            os.makedirs(args.save_blocks, exist_ok=True)
            path = os.path.join(args.save_blocks, f"block_{i}_sub{s:02x}_tgt{t:02x}.bin")
            with open(path, "wb") as f:
                f.write(blk)
            print(f"           saved -> {path}")

    if not found:
        print("\n  No reply carried the sending-card brightness signature.")
        if len(sigs) == 1:
            print("  Every query returned the SAME thing - the card is answering")
            print("  generically, so sub/target sweeping will not find it.")
        print("  The reliable next step is a capture: open HDset's *Sending Card")
        print("  Parameters* screen (which must read the wall to populate itself)")
        print("  and capture that, then run hd_bright_analyze.py --dump on it.")
        return 1

    sub, tgt, p = found
    print(f"  FOUND: class 0x01 sub 0x{sub:02x} target 0x{tgt:02x} returns the "
          f"sending-card block")
    print(f"         level={p[PCT_OFFS[0]]}%  auto={p[AUTO_OFF]}  EDID={EDID_MAGIC in p}")
    if args.save_template:
        # Store it as a class-0x02 write payload: same 512-byte body, write class,
        # and the header copied from the class-0x02 frames we captured.
        tpl = bytearray(p)
        tpl[0], tpl[1], tpl[3] = 0x02, 0x00, 0x00
        with open(args.save_template, "wb") as f:
            f.write(bytes(tpl))
        print(f"  saved template -> {args.save_template}")
        print("  VERIFY before trusting it: hd_bright.py --set <same level> --dry-run")
        print("  and compare against a captured frame if you have one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
