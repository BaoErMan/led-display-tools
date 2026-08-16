#!/usr/bin/env python3
"""find_config.py - locate the Huidu sending-card block inside HDset's own saved
files, so a fleet client can build its brightness template from disk instead of
from a USB capture.

Why this might work
-------------------
HDset's *Sending Card Parameters* screen sends NOTHING when opened
(sending_card_read.pcapng: zero bulk writes), so it populates itself from local
data. The 521-byte block it later transmits must therefore be derivable from
something on the config machine. If HDset stores that block - or the fields that
make it up - we can provision every wall with no sniffer at all.

How it searches
---------------
Using signatures taken from two DIFFERENT walls' blocks, so they are
wall-independent (the 15 bytes that differ between walls are excluded):

    EDID magic       00ffffffffffff00   at payload offset 265
    dense 48B run    08180103811e17aa…  at payload offset 281  (47/48 non-zero)
    model string     "HD 1920X1080"     at payload offset 360

On a hit it reconstructs a candidate payload - trying both "the file holds the
whole payload" and "the file holds only the 512-byte data area" - and validates
it with the brightness signature before believing it.

    python find_config.py --scan "C:/Program Files (x86)/HDSet"
    python find_config.py --scan ~/hdset_files --ext .cfg,.dat,.bin
    python find_config.py --scan DIR --extract wall.bin

If nothing hits, HDset is storing the fields in some other form (compressed,
encrypted, or as separate settings it assembles at send time) and the block would
have to be rebuilt field by field rather than copied.
"""
import argparse
import base64
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hd_bright import (is_brightness_block, FRAME_LEN, PCT_OFFS,  # noqa: E402
                       AUTO_OFF, BRIGHT_CLASS, BRIGHT_SUB)

HEADER_LEN = 9

# The 9-byte protocol header, identical in both walls' blocks. Always written
# fresh onto an extracted block: a file may hold only the data area, in which
# case whatever precedes it is not a header at all, and emitting it would send
# the wrong command class.
CANON_HEADER = bytes([BRIGHT_CLASS, BRIGHT_SUB, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x02, 0x00])

# (name, bytes, offset within the 521-byte payload). All verified identical
# across two different walls, so they identify the block, not the wall.
SIGNATURES = [
    ("edid-magic", bytes.fromhex("00ffffffffffff00"), 265),
    ("dense-48",   bytes.fromhex(
        "08180103811e17aaeaf8d0a3574e9c231d5054bfee00"
        "01010101010101010101010101010101423b803d713832404088"), 281),
    ("model-str",  b"HD 1920X1080", 360),
]

DEFAULT_MAX_MB = 200


def iter_files(root, exts=None, max_mb=DEFAULT_MAX_MB):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            if exts and os.path.splitext(n)[1].lower() not in exts:
                continue
            try:
                if os.path.getsize(p) > max_mb * 1024 * 1024:
                    continue
            except OSError:
                continue
            yield p


def candidates_from_hit(data, hit_off, sig_off):
    """Reconstruct possible 521-byte payloads from a signature hit.

    Two layouts are plausible and both are tried: the file may hold the whole
    payload (header included), or only the 512-byte data area with HDset adding
    the 9-byte protocol header at send time."""
    out = []
    # (a) file holds the full payload
    start = hit_off - sig_off
    if 0 <= start and start + FRAME_LEN <= len(data):
        out.append(("full-payload", start,
                    CANON_HEADER + bytes(data[start + HEADER_LEN:start + FRAME_LEN])))
    # (b) file holds only the data area; the header is added at send time
    start_d = hit_off - (sig_off - HEADER_LEN)
    if 0 <= start_d and start_d + (FRAME_LEN - HEADER_LEN) <= len(data):
        body = bytes(data[start_d:start_d + FRAME_LEN - HEADER_LEN])
        out.append(("data-area", start_d, CANON_HEADER + body))
    return out


B64_RE = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")


def decoded_layers(data, depth=2):
    """Yield (label, bytes) for base64 payloads nested inside `data`.

    HDset does not store the block as raw bytes: net_default_new.xml holds
    SendCardPage as base64, which decodes to another XML whose
    SendCardBasicBin Card0 attribute is base64 again - the block is two layers
    down. Decoding generically rather than hard-coding that path means the
    search still works if the nesting or element names change between versions.
    """
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
        yield (f"base64@{m.start()}", dec)
        for label, sub in decoded_layers(dec, depth - 1):
            yield (f"base64@{m.start()}>{label}", sub)


def _scan_bytes(data, origin, good, raw, seen):
    for name, sig, sig_off in SIGNATURES:
        start = 0
        while True:
            i = data.find(sig, start)
            if i < 0:
                break
            start = i + 1
            raw.append((name, i, origin))
            for layout, off, payload in candidates_from_hit(data, i, sig_off):
                # Each signature x layout rediscovers the same block, so report
                # it once rather than six times.
                if payload in seen or not is_brightness_block(payload):
                    continue
                seen.add(payload)
                good.append((name, off, f"{layout} [{origin}]", payload))


def scan_file(path, verbose=False):
    """[(signature, offset, layout, payload)] for validated blocks, plus raw
    signature hits. Searches the file's own bytes and any base64 nested in it."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return [], []
    good, raw, seen = [], [], set()
    _scan_bytes(data, "raw", good, raw, seen)
    for label, blob in decoded_layers(data):
        _scan_bytes(blob, label, good, raw, seen)
    return good, raw


def explain(path):
    """Diagnose a single config file: what it contains and where the chain to the
    block breaks. Turns 'not found' into something actionable."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"cannot read {path}: {e}")
        return 1
    print(f"== {path}: {len(data)} bytes ==")
    for el in (b"SendCardPage", b"SendCardBasicBin", b"RecvCardPage",
               b"TransmittedData", b"BoxHwConfig", b"Card0"):
        print(f"  contains {el.decode():17}: {el in data}")
    layers = list(decoded_layers(data))
    print(f"\n  {len(layers)} base64 layer(s) decoded:")
    for label, blob in layers[:12]:
        head = blob[:40]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in head)
        kind = "XML" if blob.lstrip()[:5] == b"<?xml" else "binary"
        marks = [n for n in (b"SendCardBasicBin", b"Card0", b"HD 1920X1080")
                 if n in blob]
        print(f"    {label:28} {len(blob):6}B {kind:6} {txt}")
        if marks:
            print(f"        contains: {', '.join(m.decode() for m in marks)}")
    good, _raw = scan_file(path)
    print(f"\n  validated blocks: {len(good)}")
    if not good:
        if b"SendCardBasicBin" not in data and not any(
                b"SendCardBasicBin" in b for _l, b in layers):
            print("  -> No SendCardBasicBin anywhere. This file does not hold a")
            print("     sending-card config. Either HDset has not saved one for")
            print("     this screen yet, or this install keeps it elsewhere -")
            print("     scan the whole tree:  find_config.py --scan <HDset dir>")
        else:
            print("  -> SendCardBasicBin is present but its block did not")
            print("     validate. Send a brightness change in HDset so it")
            print("     rewrites the config, then re-run.")
    return 0 if good else 1


def main():
    ap = argparse.ArgumentParser(
        description="Find the Huidu sending-card block in HDset's saved files")
    ap.add_argument("--scan", metavar="PATH",
                    help="file or directory to search (not needed with --explain)")
    ap.add_argument("--ext", default=None,
                    help="comma-separated extensions to limit to (default: all)")
    ap.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB)
    ap.add_argument("--extract", metavar="OUT",
                    help="write the first validated block as a template")
    ap.add_argument("--verbose", action="store_true",
                    help="also report signature hits that failed validation")
    ap.add_argument("--explain", metavar="FILE",
                    help="diagnose one file: what base64 layers and known "
                         "elements it holds, and why no block was found")
    args = ap.parse_args()

    if args.explain:
        return explain(args.explain)

    if not args.scan:
        ap.error("give --scan PATH (a file or the HDset folder), or --explain FILE")

    exts = None
    if args.ext:
        exts = {e if e.startswith(".") else "." + e
                for e in (x.strip().lower() for x in args.ext.split(",")) if e}

    n_files = 0
    all_good, all_raw = [], []
    for p in iter_files(args.scan, exts, args.max_mb):
        n_files += 1
        good, raw = scan_file(p)
        for g in good:
            all_good.append((p,) + g)
        for r in raw:
            all_raw.append((p,) + r)

    print(f"== scanned {n_files} file(s) under {args.scan} ==")
    if all_raw:
        print(f"\n  {len(all_raw)} raw signature hit(s):")
        seen = set()
        for path, name, off, *_o in all_raw[:40]:
            if (path, name) in seen:
                continue
            seen.add((path, name))
            print(f"    {name:11} @ 0x{off:x}  {path}")
    if not all_good:
        print("\n  No VALIDATED sending-card block found.")
        if all_raw:
            print("  Signatures matched but the surrounding bytes were not a")
            print("  well-formed block - HDset may store the fields separately")
            print("  and assemble the block only when sending.")
        else:
            print("  Nothing matched at all. The config is probably compressed,")
            print("  encrypted, or stored field-by-field rather than as the block.")
            print("  Try --ext to widen the search, or point --scan at HDset's")
            print("  AppData/project folder as well as its install directory.")
        return 1

    print(f"\n  {len(all_good)} VALIDATED block(s):")
    for path, name, off, layout, payload in all_good:
        print(f"    {path}")
        print(f"      via {name}, {layout}, block at 0x{off:x}  "
              f"level={payload[PCT_OFFS[0]]}%  auto={payload[AUTO_OFF]}")
    if args.extract:
        payload = all_good[0][4]
        with open(args.extract, "wb") as f:
            f.write(payload)
        print(f"\n  wrote {args.extract} ({len(payload)} bytes)")
        print("  VERIFY before trusting it on hardware: compare against a")
        print("  captured frame from that wall, and record a fingerprint with")
        print("  hd_bright.py --save-fingerprint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
