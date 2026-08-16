#!/usr/bin/env python3
"""bright_analyze.py - Find the NovaStar brightness command/register by diffing a
SET of ataradov captures taken at known brightness levels.

Idea: everything in ../PROTOCOL.md is reads. Brightness is where NovaLCT issues
`cmd=0x01` WRITES. If we capture the same "set brightness" action at several
known levels, exactly one frame field (a data byte at some offset under some
register selector) will track the level. This tool finds it automatically, in
BOTH directions:
  * H>D write frames (cmd=0x01) - the value NovaLCT pushes to the card
  * D>H reply frames            - the value the card reports back (read path)

Input: pcaps whose filename encodes the level, e.g.
    set_100.pcap  set_75.pcap  set_50.pcap  set_25.pcap  set_10.pcap
The integer run of digits in the name is the level (percent). Pass them on the
command line, or drop them in this dir and run with no args (globs set_*.pcap).

    python bright_analyze.py                    # globs ./set_*.pcap
    python bright_analyze.py a.pcap:100 b.pcap:50   # explicit file:level
    python bright_analyze.py --dump set_50.pcap     # just decode one capture
    python bright_analyze.py --writes slide.pcap    # list cmd=0x01 writes in order
                                                    #  (use on a 'move the slider' capture)

Reuses ../extract.py (bulk-pipe autodetect + reassembly) and ../analyze.py
(frame split + checksum). Requires tshark on PATH.
"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NOVA = os.path.dirname(HERE)                     # ../ (nova_probe_re)
sys.path.insert(0, NOVA)

import extract                                    # noqa: E402
import analyze                                    # noqa: E402


def frames_for(pcap):
    """Reassemble one pcap and return [(dir, frame_bytes), ...] checksum-valid.
    Resets extract's autodetected pipe so each capture is detected fresh."""
    extract.DEV_ADDR = None
    extract.BULK_EP = None
    out = []
    for _, d, burst in extract.reassemble(pcap):
        for f in analyze.split_frames(burst):
            out.append((d, f))
    return out


def selector(f):
    """A frame's routing key: (dir-independent) dev, port, idx, cmd, reg."""
    dev, port = f[6], f[7]
    idx = int.from_bytes(f[8:10], "little")
    cmd = f[10]
    reg = f[11:16].hex()
    return (dev, port, idx, cmd, reg)


def level_from_name(name):
    m = re.search(r"(\d+)", os.path.basename(name))
    return int(m.group(1)) if m else None


def parse_args(argv):
    """Return [(pcap, level), ...]. Accepts 'file:level' or bare 'file' (level
    parsed from the digits in the filename)."""
    items = []
    for a in argv:
        if ":" in a and not a.endswith(".pcap"):
            path, lvl = a.rsplit(":", 1)
            items.append((path, int(lvl)))
        else:
            lvl = level_from_name(a)
            if lvl is None:
                sys.exit(f"cannot read a level from '{a}' - use file:level")
            items.append((a, lvl))
    return items


def dump(pcap):
    """Decode a single capture into the analyze.py table (all frames)."""
    fs = frames_for(pcap)
    print(f"== {os.path.basename(pcap)}: {len(fs)} checksum-valid frames ==")
    analyze.show(fs)


def check(pcap):
    """Capture-health check. The ataradov sniffer emits Syslog 'USB PHY error'
    when it can't lock onto the bus (usually a Full/Low/High SPEED mismatch —
    the CP210x is Full-Speed). A healthy capture is almost all clean USBLL with a
    detectable bulk pipe; a dud is mostly PHY errors and line-state noise."""
    import subprocess

    def count(dfilter):
        r = subprocess.run(["tshark", "-r", pcap, "-Y", dfilter, "-T", "fields",
                            "-e", "frame.number"], capture_output=True, text=True)
        return sum(1 for ln in r.stdout.splitlines() if ln.strip())

    usbll = count("usbll")
    phy = count('syslog.msg contains "PHY error"')
    data = count("usbll.pid==0xc3 || usbll.pid==0x4b")          # DATA0/DATA1
    tokens = count("usbll.pid==0x69 || usbll.pid==0xe1")        # IN/OUT
    extract.DEV_ADDR = extract.BULK_EP = None
    addr, endp = extract.detect_bulk_pipe(pcap)

    print(f"== {os.path.basename(pcap)} health ==")
    print(f"  USBLL pkts : {usbll}")
    print(f"  PHY errors : {phy}")
    print(f"  DATA pkts  : {data}")
    print(f"  IN/OUT toks: {tokens}")
    print(f"  bulk pipe  : device {addr} endpoint {endp}")
    good = addr is not None and data > 0 and phy < max(50, data)
    if good:
        print("  -> GOOD: usable USB traffic; run --writes / correlate on it.")
    elif usbll < 100 and phy < 50:
        print("  -> BAD (EMPTY): almost no USB traffic captured. The sniffer wasn't")
        print("     recording, the window was too short, or the device/NovaLCT wasn't")
        print("     talking. Arm the sniffer, keep the target screen actively polling,")
        print("     and capture for a few seconds before saving.")
    else:
        print("  -> BAD (PHY): sniffer didn't decode the bus (PHY errors dominate).")
        print("     Re-capture with the sniffer set to FULL SPEED (CP210x = 12Mbps),")
        print("     confirm the device is enumerated and NovaLCT is actively polling.")
    return good


def writes(pcap):
    """List every cmd=0x01 WRITE (H>D) in order. This is what a 'move the slider'
    capture records: each write carries the value NovaLCT pushed. Reading the
    value progression down the list reveals the brightness byte + its offset."""
    dev_t = {0: "sending", 1: "recv"}
    ws = [f for d, f in frames_for(pcap) if d == "H>D" and f[10] == 0x01]
    print(f"== {os.path.basename(pcap)}: {len(ws)} write frame(s) ==")
    if not ws:
        print("  no cmd=0x01 writes here — was the slider moved during capture?")
        return
    print(" ser dev      port idx  reg           len  data")
    for f in ws:
        dev, port = f[6], f[7]
        idx = int.from_bytes(f[8:10], "little")
        reg = f[11:16].hex()
        dlen = int.from_bytes(f[16:18], "little")
        data = f[18:18 + dlen]
        dd = data.hex() if dlen <= 24 else data[:24].hex() + f"…(+{dlen-24}B)"
        print(f" {f[3]:3d} {dev:02x}({dev_t.get(dev,'?'):7}) {port:02x}  {idx:04x} "
              f"{reg} {dlen:4d}  {dd}")


def correlate(captures):
    """captures: {level: [(dir, frame), ...]}. For every (dir, selector) present
    in >=3 levels, find data-byte offsets whose value tracks the level."""
    levels = sorted(captures)
    # gather, per (dir, selector), the data payload seen at each level.
    # if a selector fires multiple times in one capture we keep the first with
    # non-empty data (writes/replies carry the payload we care about).
    table = {}                                   # (dir, selector) -> {level: data}
    for lvl in levels:
        for d, f in captures[lvl]:
            dlen = int.from_bytes(f[16:18], "little")
            data = f[18:18 + dlen]
            if not data:
                continue
            key = (d, selector(f))
            table.setdefault(key, {}).setdefault(lvl, data)

    print(f"\n== correlating {len(table)} (dir,selector) payload groups over "
          f"levels {levels} ==")
    hits = []
    for (d, sel), per_lvl in table.items():
        seen = sorted(per_lvl)
        if len(seen) < 3:
            continue
        minlen = min(len(per_lvl[l]) for l in seen)
        for off in range(minlen):
            vals = [per_lvl[l][off] for l in seen]
            if len(set(vals)) < 2:
                continue                          # constant byte - not it
            if _monotonic(seen, vals):
                hits.append((d, sel, off, list(zip(seen, vals))))

    if not hits:
        print("  no byte tracked the level. Check the captures actually differ,")
        print("  or widen the level spread. Run --dump on one to eyeball frames.")
        return
    dev_t = {0: "sending", 1: "recv"}
    for d, sel, off, pairs in sorted(hits, key=lambda h: -_fit_quality(h[3])):
        dev, port, idx, cmd, reg = sel
        tag = "WRITE" if cmd == 1 else "read "
        arrow = "H>D" if d == "H>D" else "D>H"
        print(f"\n  [{arrow} {tag}] dev={dev}({dev_t.get(dev,'?')}) port={port} "
              f"idx={idx} reg={reg}  -> data byte offset {off}")
        for lvl, v in pairs:
            pct255 = round(v / 255 * 100)
            print(f"      level {lvl:3d}%  ->  byte 0x{v:02x} ({v:3d})"
                  f"   [{v}/255 = {pct255}%]")
        print(f"      mapping guess: {_guess_formula(pairs)}")


def _monotonic(levels, vals):
    inc = all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1))
    dec = all(vals[i] >= vals[i + 1] for i in range(len(vals) - 1))
    return inc or dec


def _fit_quality(pairs):
    """Rank candidates: prefer ones matching level==byte or byte==level/100*255."""
    err_direct = sum(abs(v - l) for l, v in pairs)
    err_255 = sum(abs(v - round(l / 100 * 255)) for l, v in pairs)
    return -min(err_direct, err_255)


def _guess_formula(pairs):
    err_direct = sum(abs(v - l) for l, v in pairs)
    err_255 = sum(abs(v - round(l / 100 * 255)) for l, v in pairs)
    if err_direct <= err_255 and err_direct <= len(pairs):
        return "byte == level (percent stored directly)"
    if err_255 < err_direct and err_255 <= len(pairs):
        return "byte == round(level/100 * 255)  (0-255 scale)"
    return f"nonlinear/unknown (|err| direct={err_direct}, 0-255={err_255})"


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "--dump":
        for p in argv[1:] or sys.exit("--dump needs a pcap"):
            dump(p)
        return
    if argv and argv[0] == "--writes":
        for p in argv[1:] or sys.exit("--writes needs a pcap"):
            writes(p)
        return
    if argv and argv[0] == "--check":
        for p in argv[1:] or sys.exit("--check needs a pcap"):
            check(p)
        return
    items = parse_args(argv) if argv else \
        [(p, level_from_name(p)) for p in sorted(glob.glob(os.path.join(HERE, "set_*.pcap")))]
    if not items:
        sys.exit(__doc__)
    captures = {}
    for pcap, lvl in items:
        print(f"-- {os.path.basename(pcap)}  (level {lvl}%)")
        captures[lvl] = frames_for(pcap)
        print(f"   {len(captures[lvl])} frames")
    correlate(captures)


if __name__ == "__main__":
    main()
