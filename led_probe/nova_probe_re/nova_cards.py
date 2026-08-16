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

    What ends it, once the clamp probe has shown this controller answers past the
    end of a chain: CLAMP_RUN consecutive IDENTICAL blocks - whether or not they
    equal the clamp value. Requiring them to equal the clamp was not enough: on a
    live MCTRL600 port 1 returned an odd block for the clamp probe, so the real
    tail (240x80 repeating) never matched it and the walk read all 128 indices.
    Beyond a repeat that long the tail length is unknowable anyway, so reading on
    buys nothing.

    That stop applies ONLY when clamp_dig is set. A controller that properly ends
    a chain gives an exact count, and must keep walking through any number of
    identical cards to get it.
    """
    clamp = _block(ser, port, max_idx + CLAMP_PROBE, seq)
    clamp_dig = _digest(clamp) if parse_geometry(clamp) else None

    runs, prev, repeat = [], None, 0
    idx = 0
    while idx <= max_idx:
        data = _block(ser, port, idx, seq)
        geo = parse_geometry(data)
        dig = _digest(data) if geo else None
        if on_read:
            on_read(port, idx, geo, dig, dig is not None and dig == clamp_dig,
                    data)
        if not geo:
            return runs, False                      # unused port / real end of chain
        if dig == prev:
            runs[-1]["last"] = idx
            repeat += 1
        else:
            runs.append({"first": idx, "last": idx, "geometry": list(geo),
                         "digest": dig, "hint": data[HEIGHT_HINT_OFF],
                         "params": [data[o] for o in PARAM_OFFSETS]})
            prev = dig
            repeat = 1
        if clamp_dig and repeat >= CLAMP_RUN:
            runs[-1]["open_ended"] = True
            return _drop_echo(runs, clamp_dig), True
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


def parse_ack(spec):
    """{(port0, idx)} from ["1:0", ...] - the cards a human has confirmed are
    deliberate. Written the way the dashboard SHOWS them: 1-based port, 0-based
    index, so "1:0" is the "port 1 index 0" in the warning being acknowledged.

    Accepts a list or a comma-separated string; unparseable entries are ignored
    rather than raised, because a typo in config must not stop a wall reporting.
    """
    if not spec:
        return set()
    if isinstance(spec, str):
        spec = spec.split(",")
    out = set()
    for item in spec:
        try:
            port, idx = str(item).strip().split(":")
            out.add((int(port) - 1, int(idx)))
        except (ValueError, AttributeError):
            continue
    return out


def check_consistency(ports, ack=()):
    """Flag blocks whose geometry disagrees with others sharing their driver
    parameters. That mismatch is what a misconfigured card looks like.

    Cards in `ack` are known-deliberate and produce no issue. A live wall carries
    a 240x20 strip added to compensate for shipping damage: correct by design, but
    it matches no other card and would otherwise warn on every survey forever,
    which is how people learn to ignore warnings. It still appears in the geometry.
    """
    ack = ack if isinstance(ack, set) else parse_ack(ack)
    by_params = {}
    for p in ports:
        for r in p["runs"]:
            by_params.setdefault(tuple(r["params"]), []).append((p["port"], r))
    issues, acked = [], []

    def report(pt, idx, msg, advice):
        # An acknowledged card keeps the description but drops the call to action:
        # telling someone to go check a card they have already confirmed is how a
        # report trains people to skim past it.
        if (pt, idx) in ack:
            acked.append(f"port {pt+1} index {idx}: {msg}")
        else:
            issues.append(f"port {pt+1} index {idx}: {msg} - {advice}")

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
                    report(pt, r["first"],
                           f"geometry {g[0]}x{g[1]} but its driver parameters match "
                           f"the {majority[0]}x{majority[1]} cards",
                           "likely a misconfigured card")

    # The ODD ONE OUT: a single card whose driver parameters match no other card
    # on the wall. The check above can never see it - it only compares geometry
    # WITHIN a parameter group, and a card like this is alone in its own group,
    # so nothing is ever compared and the survey reported "all cards consistent".
    # That is how a 240x20 block with params[2 8 0 32] sat unflagged on a live
    # wall between 240x100s (params[10 16 255 255]) and 240x80s (params[8 8 ...]).
    if len(by_params) > 1:
        for _params, entries in by_params.items():
            if len(entries) != 1:
                continue
            pt, r = entries[0]
            if r["first"] != r["last"]:
                continue      # a whole RUN of them is a panel type, not a stray
            g = r["geometry"]
            report(pt, r["first"],
                   f"{g[0]}x{g[1]}, driver parameters {r['params']} match no other "
                   f"card on this wall",
                   "check this card in NovaLCT (a blank or wrongly configured slot "
                   "looks like this)")
    return issues, acked


def survey(ser, ports=4, max_idx=127, seq=None, on_read=None, warmup=1, ack=()):
    """Full survey. Returns a dict safe to serialise and report.

    `warmup` throwaway reads run first because the FIRST transaction of a session
    is not trustworthy: on a live MCTRL600 the very first read (port 1's clamp
    probe) returned a 240x20 block that port 2's identical probe never produced,
    and the next read repeated it. Discarding a read costs nothing and keeps that
    artifact out of the clamp value, which every later decision depends on.
    """
    seq = seq or Seq()
    for _ in range(max(0, warmup)):
        _block(ser, 0, 0, seq)
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
    issues, acked = check_consistency(live, ack)
    return {"ports": out, "count": count, "count_note": note,
            "issues": issues, "acked": acked}


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
    for a in s.get("acked", []):
        # Shown, but not an issue: someone confirmed this card is deliberate.
        lines.append(f"  · acknowledged: {a}")
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
    ap.add_argument("--ack", default=None,
                    help="cards known to be deliberate, as PORT:IDX "
                         "(1-based port, as shown in the warning), "
                         "comma-separated e.g. --ack 1:0")
    ap.add_argument("--warmup", type=int, default=1,
                    help="throwaway reads before surveying; the first\n                          transaction of a session is unreliable")
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
    def trace(port, idx, geo, dig, is_clamp, data):
        if geo:
            # hint = offset 22 (~height/20) and the driver params: the fields the
            # consistency check groups on, shown raw so an odd card is visible.
            prm = " ".join(f"{data[o]:3d}" for o in PARAM_OFFSETS)
            print(f"  port {port+1} idx {idx:3d}: {geo[0]:4d}x{geo[1]:<4d} "
                  f"{dig}  hint={data[HEIGHT_HINT_OFF]:3d}  params[{prm}]"
                  f"{'  == clamp' if is_clamp else ''}")
        else:
            print(f"  port {port+1} idx {idx:3d}: no geometry (end of chain)")

    if args.walk:
        print(f"== {args.port} @ {baud}  raw walk ==")
    try:
        s = survey(ser, args.ports, args.max_idx,
                   on_read=trace if args.walk else None,
                   warmup=args.warmup, ack=parse_ack(args.ack))
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
