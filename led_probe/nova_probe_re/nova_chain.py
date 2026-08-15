#!/usr/bin/env python3
"""nova_chain.py - what does a NovaStar port actually return per card index?

Counting receiving cards by "walk indices until one does not answer" assumes an
out-of-range index stays silent. On at least one MCTRL600 that is false: index 177
answers with VALID GEOMETRY on a wall that plainly has no 178 cards. Either the
sending card CLAMPS (returns the last real card for anything beyond the end) or it
WRAPS (modulo the chain length). Both make counting-by-absence impossible, and the
two need different handling - so look before designing around it.

Read-only: config-block reads only, no writes.

    python nova_chain.py --port COM5 --ports 2
    python nova_chain.py --port COM5 --ports 4 --indices 0,1,2,3,4,8,16,32,177,250
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nova_probe import (Seq, build_read, transact, RX_BLOCK,  # noqa: E402
                        parse_geometry, DEFAULT_BAUD)
from nova_bright import detect_baud, open_serial                # noqa: E402

DEFAULT_INDICES = "0,1,2,3,4,5,6,7,8,12,16,24,32,48,64,96,127,177,250"


def block_at(ser, port, idx, seq):
    reps = transact(ser, build_read(seq.next(), 0x01, port, idx, RX_BLOCK, 256))
    return reps[0]["data"] if reps else b""


def main():
    ap = argparse.ArgumentParser(description="Probe a NovaStar port index by index")
    default_port = "COM5" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=None)
    ap.add_argument("--ports", type=int, default=2)
    ap.add_argument("--indices", default=DEFAULT_INDICES)
    ap.add_argument("--dump", metavar="PORT:IDX", action="append", default=None,
                    help="print the full config block for a port:index, e.g. "
                         "--dump 1:0 --dump 1:6 --dump 2:6 (ports are 1-based). "
                         "Repeatable; blocks are diffed against the first.")
    args = ap.parse_args()

    idxs = [int(x) for x in args.indices.split(",") if x.strip()]
    if args.baud:
        ser, baud = open_serial(args.port, args.baud), args.baud
    else:
        ser, baud = detect_baud(args.port)
        if ser is None:
            sys.exit(f"nothing answered on {args.port}")
    print(f"== {args.port} @ {baud} ==")
    seq = Seq()
    if args.dump:
        try:
            blocks = []
            for spec in args.dump:
                pt, ix = (int(x) for x in spec.split(":"))
                data = block_at(ser, pt - 1, ix, seq)
                blocks.append((spec, data))
                geo = parse_geometry(data)
                print(f"\n-- port {pt} index {ix}  ({len(data)}B, geometry "
                      f"{geo if geo else 'none'}) --")
                for off in range(0, min(len(data), 128), 16):
                    row = data[off:off + 16]
                    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
                    print(f"   {off:4d}  {row.hex(' ')}  {asc}")
                if len(data) > 128:
                    print(f"   … {len(data)-128} more bytes")
            if len(blocks) > 1:
                base_name, base = blocks[0]
                print(f"\n-- differences vs {base_name} --")
                for name, data in blocks[1:]:
                    d = [i for i in range(min(len(base), len(data)))
                         if base[i] != data[i]]
                    print(f"   {name}: {len(d)} byte(s) differ"
                          + (f"  at offsets {d[:24]}" if d else ""))
                    for i in d[:16]:
                        print(f"      off {i:3d}: {base_name}={base[i]:3d}  "
                              f"{name}={data[i]:3d}")
        finally:
            ser.close()
        return 0
    try:
        for port in range(args.ports):
            print(f"\n  port {port + 1}:")
            print("    idx   geometry     block digest   same as previous?")
            prev = None
            digests = {}
            for i in idxs:
                data = block_at(ser, port, i, seq)
                geo = parse_geometry(data)
                dig = hashlib.sha1(data).hexdigest()[:8] if data else "-"
                same = "yes" if (prev is not None and dig == prev) else ""
                digests.setdefault(dig, []).append(i)
                print(f"    {i:4d}  {str(geo) if geo else 'none':<12} {dig:<14} {same}")
                prev = dig
            distinct = {d: v for d, v in digests.items() if d != "-"}
            print(f"    -> {len(distinct)} distinct block(s) across {len(idxs)} indices")
            if len(distinct) == 1:
                print("       every index returns the SAME block: the port clamps or")
                print("       echoes, so cards cannot be counted by walking indices.")
            elif distinct:
                big = max(distinct.items(), key=lambda kv: len(kv[1]))
                if len(big[1]) > 1:
                    print(f"       block {big[0]} repeats at indices {big[1][:12]}")
                    print("       - if those are the HIGH indices, that is the clamp")
                    print("         value and the real chain ends before them.")
    finally:
        ser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
