#!/usr/bin/env python3
"""nova_cards.py - survey a NovaStar wall's receiving cards and flag any whose
configuration disagrees with its peers.

NovaStar-only. Huidu walls are not touched: their protocol has no equivalent
readback and the client must not send NovaStar frames to them.

What it does
------------
Walks each output port collecting DISTINCT receiving-card config blocks and the
index range each covers, then groups the blocks by their driver parameters and
checks that every block sharing a parameter set also shares a geometry. A block
that does not is a misconfigured card - found exactly this way on a real wall: a
240x80 panel still carrying a 240x100 height.

Counting caveat (deliberate)
----------------------------
An MCTRL600 answers OUT-OF-RANGE indices, returning the last card's block for
anything past the end of the chain. Two identical cards at the end are therefore
indistinguishable from one card plus the clamp, so an exact card count is NOT
derivable there. `count` is None in that case and `count_note` says why - better
than a confident wrong number.

    python nova_cards.py --port COM5 --ports 4
    python nova_cards.py --port COM5 --ports 4 --json
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nova_probe import (Seq, build_read, transact, RX_BLOCK,   # noqa: E402
                        parse_geometry)

# The DRIVER/scan parameters that a panel type implies. Offset 22 is deliberately
# EXCLUDED: it tracks height (5 for 100px, 4 for 80px), so including it split the
# good and bad cards into different groups and the mismatch was never compared -
# the check silently passed on the very wall that had the fault. Group by what the
# panel's driver needs, then verify the geometry agrees.
PARAM_OFFSETS = (27, 34, 93, 94)
HEIGHT_HINT_OFF = 22          # ~height/20; cross-checked separately
GEO_OFFSETS = (23, 24, 25, 26)
CLAMP_PROBE = 50         # how far past max_idx to look for the clamp value

# How many CONSECUTIVE clamp-valued blocks to accept before calling it the echo
# and stopping. This must exceed the longest run of identical cards a real wall
# can have, or the walk stops inside a real run and loses everything after it -
# which is exactly what stopping on the FIRST clamp match did: a wall whose last
# card matches the clamp had that card reported as the end of the chain, hiding
# every card behind it. Overshooting only costs reads and an open-ended tail.
CLAMP_RUN = 16


def _digest(b):
    return hashlib.sha1(b).hexdigest()[:8]


def _block(ser, port, idx, seq):
    reps = transact(ser, build_read(seq.next(), 0x01, port, idx, RX_BLOCK, 256))
    return reps[0]["data"] if reps else b""


def survey_port(ser, port, seq, max_idx=127, on_read=None):
    """[{first, last, geometry, params, digest}] of distinct blocks on one port,
    plus whether the walk ran into the controller's clamp value.

    The clamp block is identified FIRST, by reading an index far past any real
    chain. Two things must NOT end the walk:

      * a block merely repeating - six identical cards in a row is a normal wall,
        and treating that as the end hid a misconfigured card behind it;
      * the FIRST block matching the clamp - on a wall whose last cards match the
        clamp value those cards are real, and stopping there reported a 7-card
        port as 1 card (observed on a live MCTRL600, port 1 idx 0).

    Only a run of CLAMP_RUN consecutive clamp-valued blocks ends it, and the run
    it ends is marked open_ended: its true length is not knowable from the link.
    """
    clamp = _block(ser, port, max_idx + CLAMP_PROBE, seq)
    clamp_dig = _digest(clamp) if parse_geometry(clamp) else None

    runs, prev, clamp_run = [], None, 0
    idx = 0
    while idx <= max_idx:
        data = _block(ser, port, idx, seq)
        geo = parse_geometry(data)
        dig = _digest(data) if geo else None
        if on_read:
            on_read(port, idx, geo, dig, dig is not None and dig == clamp_dig)
        if not geo:
            return runs, False                      # unused port / real end of chain
        if dig == prev:
            runs[-1]["last"] = idx
        else:
            runs.append({"first": idx, "last": idx, "geometry": list(geo),
                         "digest": dig,
                         "params": [data[o] for o in PARAM_OFFSETS]})
            prev = dig
        if clamp_dig and dig == clamp_dig:
            clamp_run += 1
            if clamp_run >= CLAMP_RUN:
                runs[-1]["open_ended"] = True
                return _drop_echo(runs, clamp_dig), True
        else:
            clamp_run = 0                           # a real block broke the run
        idx += 1
    # Ran the whole range without an end: the controller answers everything.
    if runs:
        runs[-1]["open_ended"] = True
    return _drop_echo(runs, clamp_dig), True


def _drop_echo(runs, clamp_dig):
    """Discard a trailing open-ended run that merely repeats an earlier block.

    Once past the end of a chain the controller keeps answering with the clamp
    value, so a wall like [100px, 80px] reports a third run of 100px behind the
    80px cards. That run is the echo, not hardware: an identical block reappearing
    only AFTER a different one is the controller repeating itself.
    """
    if len(runs) > 1 and runs[-1].get("open_ended") \
            and runs[-1]["digest"] == clamp_dig \
            and any(r["digest"] == clamp_dig for r in runs[:-1]):
        runs = runs[:-1]
        runs[-1]["open_ended"] = True
    return runs


def check_consistency(ports):
    """Flag blocks whose geometry disagrees with others sharing their driver
    parameters. That mismatch is what a misconfigured card looks like."""
    by_params = {}
    for p in ports:
        for r in p["runs"]:
            by_params.setdefault(tuple(r["params"]), []).append((p["port"], r))
    issues = []
    for params, entries in by_params.items():
        geos = {tuple(r["geometry"]) for _pt, r in entries}
        if len(geos) > 1:
            # Same driver parameters, different geometry -> one of them is wrong.
            counts = {}
            for _pt, r in entries:
                counts[tuple(r["geometry"])] = counts.get(tuple(r["geometry"]), 0) + 1
            majority = max(counts, key=counts.get)
            for pt, r in entries:
                g = tuple(r["geometry"])
                if g != majority:
                    issues.append(
                        f"port {pt+1} index {r['first']}: geometry {g[0]}x{g[1]} but its "
                        f"driver parameters match the {majority[0]}x{majority[1]} cards "
                        f"- likely a misconfigured card")
    return issues


def survey(ser, ports=4, max_idx=127, seq=None, on_read=None):
    """Full survey. Returns a dict safe to serialise and report."""
    seq = seq or Seq()
    out, any_clamped = [], False
    for p in range(ports):
        runs, clamped = survey_port(ser, p, seq, max_idx, on_read)
        any_clamped |= clamped
        out.append({"port": p, "populated": bool(runs), "runs": runs,
                    "clamped": clamped})
    live = [p for p in out if p["populated"]]
    count, note = None, ""
    if not live:
        note = "no port returned card geometry"
    elif any_clamped:
        note = ("controller answers past the end of the chain, so an exact count "
                "is not derivable; geometry per port is reliable")
    else:
        count = sum(r["last"] + 1 for p in live for r in p["runs"][-1:])
    return {"ports": out, "count": count, "count_note": note,
            "issues": check_consistency(live)}


def _rng(r):
    """Index range of a run. An open-ended run is 'idx 6+': the controller kept
    answering, so the tail length is not knowable - do not imply a precise end."""
    if r.get("open_ended"):
        return f"idx {r['first']}+"
    return (f"idx {r['first']}" if r["first"] == r["last"]
            else f"idx {r['first']}-{r['last']}")


def describe(s):
    lines = []
    for p in s["ports"]:
        if not p["populated"]:
            lines.append(f"  port {p['port']+1}: unused")
            continue
        segs = ", ".join(f"{r['geometry'][0]}x{r['geometry'][1]} {_rng(r)}"
                         for r in p["runs"])
        lines.append(f"  port {p['port']+1}: {segs}"
                     + ("  (+clamped beyond)" if p["clamped"] else ""))
    if s["count"] is not None:
        lines.append(f"  cards: {s['count']}")
    elif s["count_note"]:
        lines.append(f"  cards: not countable - {s['count_note']}")
    for i in s["issues"]:
        lines.append(f"  ! {i}")
    if not s["issues"] and any(p["populated"] for p in s["ports"]):
        lines.append("  all cards consistent with their parameter group")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Survey NovaStar receiving cards")
    default_port = "COM5" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=None)
    ap.add_argument("--ports", type=int, default=4)
    ap.add_argument("--max-idx", type=int, default=127)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--walk", action="store_true",
                    help="print every index the survey reads, with its geometry, "
                         "block digest and whether it equals the clamp value - "
                         "the raw evidence behind the summary")
    args = ap.parse_args()

    from nova_bright import detect_baud, open_serial
    if args.baud:
        ser, baud = open_serial(args.port, args.baud), args.baud
    else:
        ser, baud = detect_baud(args.port)
        if ser is None:
            sys.exit(f"nothing answered on {args.port}")
    def trace(port, idx, geo, dig, is_clamp):
        if geo:
            print(f"  port {port+1} idx {idx:3d}: {geo[0]:4d}x{geo[1]:<4d} "
                  f"{dig}{'  == clamp' if is_clamp else ''}")
        else:
            print(f"  port {port+1} idx {idx:3d}: no geometry (end of chain)")

    if args.walk:
        print(f"== {args.port} @ {baud}  raw walk ==")
    try:
        s = survey(ser, args.ports, args.max_idx, on_read=trace if args.walk else None)
    finally:
        ser.close()
    if args.walk:
        print()
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        print(f"== {args.port} @ {baud} ==")
        print(describe(s))
    return 1 if s["issues"] else 0


if __name__ == "__main__":
    sys.exit(main())
