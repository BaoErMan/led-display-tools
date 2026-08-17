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
#
# 93 and 94 are EXCLUDED for the same reason, established on a mirrored wall
# (COM10): its ten cards run up through 1-5 and back down through 6-10, the second
# five repeating the first five's image at the same desktop origin. Every card in
# the first chain carries 93,94 = 247,1 and every card in the second carries 0,16,
# ACROSS panel types:
#     idx 0-3  200x100  27,34 = 10,16   93,94 = 247,1     cards 1-4
#     idx 4    200x80   27,34 =  8,8    93,94 = 247,1     card 5
#     idx 5    200x80   27,34 =  8,8    93,94 =   0,16    card 6
#     idx 6-9  200x100  27,34 = 10,16   93,94 =   0,16    cards 7-10
# So they identify the CHAIN, not the hardware. Including them put cards 5 and 6 -
# the same 200x80 panel - in separate groups of one, and the odd-one-out check
# reported both as "match no other card on this wall". Two false alarms on a
# correctly configured wall, and every mirrored or multi-section wall would do the
# same. 27 and 34 alone track panel type and still catch the original fault: a
# 240x80 carrying a 240x100 height groups with the real 240x80s and its geometry
# disagrees with theirs.
PARAM_OFFSETS = (27, 34)
HEIGHT_HINT_OFF = 22          # ~height/20; cross-checked separately
GEO_OFFSETS = (23, 24, 25, 26)
CLAMP_PROBE = 50         # how far past max_idx to look for the clamp value
# Extra out-of-range indices to ask when the first reply does not parse. All are
# past any real chain, and a controller that answers past the end gives the same
# block at each (verified with nova_chain.py: indices 20, 40, 100 and 177 all
# returned one block). One flaky reply must not cost the whole port its clamp.
CLAMP_PROBE_OFFSETS = (CLAMP_PROBE, CLAMP_PROBE + 23, CLAMP_PROBE + 73)

# How many CONSECUTIVE clamp-valued blocks to accept before calling it the echo
# and stopping. This must exceed the longest run of identical cards a real wall
# can have, or the walk stops inside a real run and loses everything after it -
# which is exactly what stopping on the FIRST clamp match did: a wall whose last
# card matches the clamp had that card reported as the end of the chain, hiding
# every card behind it. Overshooting only costs reads and an open-ended tail.
CLAMP_RUN = 16

# The same stop for when the clamp value could not be read at all. Higher, because
# without it we cannot tell a long uniform chain from padding and a wall may
# genuinely carry a run this long; but bounded, because the alternative - reading
# every index to max_idx - took a live COM10 walk past index 91 before it was
# interrupted, and looked like a hang.
CLAMP_RUN_BLIND = 32


def _digest(b):
    return hashlib.sha1(b).hexdigest()[:8]


def _block(ser, port, idx, seq):
    reps = transact(ser, build_read(seq.next(), 0x01, port, idx, RX_BLOCK, 256))
    return reps[0]["data"] if reps else b""


def _clamp_probe(ser, port, max_idx, seq, offsets=CLAMP_PROBE_OFFSETS):
    """Digest of what this port answers past the end of its chain, or None.

    Asks at more than one out-of-range index because ONE read decides a great
    deal: without this value the walk cannot stop early, cannot drop a trailing
    echo, and cannot recognise filler. On COM10 the read at max_idx+50 parsed in
    one session and not in the next, and nova_chain.py read the same index fine
    moments later - a transient bad reply, not a property of the port.

    A port that returns NOTHING is silent, not flaky, so it is not retried: that
    keeps an unused port as cheap as it was (one read, not three)."""
    for off in offsets:
        data = _block(ser, port, max_idx + off, seq)
        if parse_geometry(data):
            return _digest(data)
        if not data:
            return None                  # silent port; retrying only wastes time
    return None


def survey_port(ser, port, seq, max_idx=127, on_read=None):
    """(runs, clamped, clamp_digest) for one output port.

    [{first, last, geometry, params, digest}] of distinct blocks on one port,
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
    clamp_dig = _clamp_probe(ser, port, max_idx, seq)

    runs, prev, repeat, reprobed = [], None, 0, False
    idx = 0
    while idx <= max_idx:
        data = _block(ser, port, idx, seq)
        geo = parse_geometry(data)
        dig = _digest(data) if geo else None
        if on_read:
            on_read(port, idx, geo, dig, dig is not None and dig == clamp_dig,
                    data)
        if not geo:
            return runs, False, clamp_dig            # unused port / real end of chain
        if dig == prev:
            runs[-1]["last"] = idx
            repeat += 1
        else:
            runs.append({"first": idx, "last": idx, "geometry": list(geo),
                         "digest": dig, "hint": data[HEIGHT_HINT_OFF],
                         "params": [data[o] for o in PARAM_OFFSETS]})
            prev = dig
            repeat = 1
        if repeat >= CLAMP_RUN:
            if clamp_dig is None and not reprobed:
                # The probe at the top can fail transiently - observed on COM10,
                # where one session read index 177 fine and the next did not, and
                # nova_chain.py read it fine moments later. Losing it disabled this
                # stop entirely and the walk ground through all 128 indices, which
                # reads as a hang. Ask again now, once.
                reprobed = True
                clamp_dig = _clamp_probe(ser, port, max_idx, seq)
            if clamp_dig:
                runs[-1]["open_ended"] = True
                return _drop_echo(runs, clamp_dig), True, clamp_dig
            if repeat >= CLAMP_RUN_BLIND:
                # Still no clamp value. CLAMP_RUN_BLIND identical blocks in a row
                # means the tail is unknowable whether or not we know the clamp -
                # 32 real identical cards and 16 cards plus padding look the same
                # from here - so stop and say so rather than read to max_idx.
                runs[-1]["open_ended"] = True
                return runs, True, None
        idx += 1
    # Ran the whole range without an end: the controller answers everything.
    if runs:
        runs[-1]["open_ended"] = True
    return _drop_echo(runs, clamp_dig), True, clamp_dig


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


def proven_fillers(out):
    """Digests that are this controller's "no card here" value, not hardware.

    Wrong twice before, both times on a real wall, so the reasoning is spelled
    out. An out-of-range index is answered differently by different controllers:

      MCTRL300  on an UNUSED port, a SYNTHETIC block - a well-formed
                200x100/240x100 that matches no real card - at every index.
                On a USED port it answers with that port's LAST CARD, exactly as
                an MCTRL600 does: on COM10 port 2, index 177 returns the block
                the real cards at idx 6-9 return. The behaviour is per PORT, not
                per controller model, which is why nothing here consults one.
      MCTRL600  A REAL CARD's block - but not always the SAME one. Which card
                depends on how far past the end you ask (nova_model.py). On COM5
                port 1, indices just past the chain return its LAST card while
                index 177 returns its FIRST; port 2 of the same controller returns
                its last card at both distances.

                Two consequences, both benign and both seen on COM5:
                  * the probe value can differ from the port's trailing run, so
                    _drop_echo does not fire and the tail stays open-ended. That
                    is honest - the tail length is not knowable either way.
                  * where the far probe lands on the FIRST card, index 0 is
                    marked "== clamp" in a --walk. On COM5 that is the deliberate
                    240x20 strip, a real card. It survives because a run of ONE
                    index ahead of a real card is not filler; see (a) below.

    A consequence worth stating: where a port's last cards and its out-of-range
    answer are the same block, the tail length is NOT derivable - COM10 port 2
    holds ten cards and reports "200x100 idx 6+", which is the honest answer, not
    a bug to be fixed.

    "The clamp value appears ahead of a real card" was therefore not proof: on
    that MCTRL600 the first card IS the clamp value - a deliberate 240x20 strip
    at port 1 index 0 - and the rule deleted it from the survey as filler. Two
    narrower tests, either of which proves filler:

    (a) it FILLS. A clamp-valued run of >=2 consecutive indices ahead of a real
        card is the controller padding empty slots. A run of ONE index ahead of a
        real card is a card - that is the 240x20 strip, and the whole reason (a)
        counts indices instead of just looking.

    (b) it is SYNTHETIC. If the clamp appears nowhere on any port that has proven
        it holds real cards (>=2 distinct blocks), no card on this wall looks like
        it - so a port made entirely of it is empty. This is what an MCTRL300 with
        cards starting at index 0 needs, where (a) never gets its evidence.

    Neither fires on an MCTRL600: its clamp is a real card, so it appears on a
    multi-block port, and it never pads. Verified against three captured walls.
    """
    proven = set()
    # Ports that have shown >=2 distinct blocks are holding real cards, whatever
    # the clamp turns out to mean; they are the reference for test (b).
    multi = [p for p in out if len({r["digest"] for r in p["runs"]}) >= 2]
    for p in out:
        clamp_dig = p.get("clamp")
        if not clamp_dig:
            continue
        runs = p["runs"]
        first_real = next((n for n, r in enumerate(runs)
                           if r["digest"] != clamp_dig), None)
        if first_real is not None:
            if any(r["digest"] == clamp_dig and r["last"] > r["first"]
                   for r in runs[:first_real]):
                proven.add(clamp_dig)                                    # (a)
        elif multi and not any(r["digest"] == clamp_dig
                               for m in multi for r in m["runs"]):
            proven.add(clamp_dig)                                        # (b)
    return proven


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
        runs, clamped, clamp_dig = survey_port(ser, p, seq, max_idx, on_read)
        any_clamped |= clamped
        out.append({"port": p, "populated": bool(runs), "runs": runs,
                    "clamped": clamped, "clamp": clamp_dig})

    # Blocks PROVEN to be "no card at this index" rather than hardware. Proof is
    # per digest and comes from any port that showed the value in front of a real
    # card (see proven_fillers); once proven, the same value is filler wherever it
    # appears - the walls that exposed this answer the identical block on every
    # port. A port left with nothing is then empty, not populated: previously an
    # unused port reported its filler as "240x100 idx 0+" and the survey called
    # the wall consistent, while brightness was being read from that non-card.
    proven = proven_fillers(out)
    if proven:
        for p in out:
            kept = [r for r in p["runs"] if r["digest"] not in proven]
            if len(kept) != len(p["runs"]):
                p["filler_dropped"] = len(p["runs"]) - len(kept)
                p["runs"] = kept
                p["populated"] = bool(kept)
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
            # "empty" and "unused" are different findings: the first is a port
            # that ANSWERED at every index with this controller's no-card block,
            # the second returned nothing at all. Both mean no cards.
            lines.append(f"  port {p['port']+1}: "
                         + ("empty (every index returns the controller's "
                            "no-card block)" if p.get("filler_dropped")
                            else "unused"))
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
