#!/usr/bin/env python3
"""nova_model.py - capture what identifies a NovaStar sending card, together with
how that controller answers past the end of a chain.

Why this exists
---------------
Two controllers answer an OUT-OF-RANGE receiving-card index differently, and the
difference decides how the card survey must read a port:

  MCTRL600   returns a REAL CARD's block. That value legitimately appears as the
             trailing run of a populated port, and on a wall of identical panels
             EVERY real card matches it.

             WHICH card depends on HOW FAR PAST THE END you ask - there is no
             single "the clamp value" for a port. COM5, whose port 1 carries nine
             cards (240x20, 240x80, 5x 240x100, 2x 240x80) at idx 0-8:

               idx 9-22   240x80    the LAST card, repeated for every index just
                                    past the end
               idx 177    240x20    the FIRST card

             Port 2 of the same wall (six 240x100 then two 240x80) answers BOTH
             distances with its last card, so the two ports of one controller do
             not even agree. Do not read a mismatch between a far probe and a
             port's trailing run as a fault: it is the hardware.
  MCTRL300   on an UNUSED port, a "no card here" FILLER block - a well-formed
             240x100 with params[10 16 255 255] - at every index. It is not
             hardware. Past the end of a USED port it does NOT do this: COM10
             port 2 answers index 177 with the same block its real cards at
             idx 6-9 return, i.e. it clamps to the last card like an MCTRL600.
             The answer is a property of the PORT, not of the model.

nova_cards.py currently infers which it is dealing with, from whether that value
turns up in FRONT of a real card. That inference has two holes: a wall whose used
port starts at index 0 never provides the evidence, and real cards whose block is
byte-identical to the filler get discarded as filler. Both vanish if the model is
simply known, hence this capture.

It is READ-ONLY: TX_ID, TX_NSSD and RX_BLOCK reads only, the same reads the probe
and survey already make. Nothing is written to the controller or the cards.

    python nova_model.py --port COM5
    python nova_model.py --port COM3 --ports 2 --json

Run it on one wall of each controller type and keep the output: the TX_ID/TX_NSSD
bytes are the fingerprint, and the per-port section records which clamp behaviour
that fingerprint goes with.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nova_probe import (Seq, build_read, transact, parse_geometry,   # noqa: E402
                        ascii_strings, RX_BLOCK, TX_ID, TX_NSSD)

CLAMP_IDX = 177          # far past any real chain - same index nova_cards.py uses
SCAN_DEPTH = 12          # indices to sample at the head of each port


def _digest(b):
    return hashlib.sha1(b).hexdigest()[:8] if b else None


def _read(ser, seq, dev, port, idx, reg, length):
    reps = transact(ser, build_read(seq.next(), dev, port, idx, reg, length))
    return reps[0]["data"] if reps else b""


def hexdump(b, limit=64):
    return " ".join(f"{x:02x}" for x in b[:limit]) + (" …" if len(b) > limit else "")


def identify_card(ser, seq):
    """The sending card's own identity: TX_ID (serial) and TX_NSSD (info block).

    Both are captured raw. Which bytes actually separate an MCTRL300 from an
    MCTRL600 is exactly what we do not know yet, so nothing is interpreted here
    beyond pulling out any printable strings - guessing a model field from one
    sample is how you get a rule that breaks on the third controller.
    """
    out = {}
    for name, reg, length in (("tx_id", TX_ID, 8), ("tx_nssd", TX_NSSD, 256)):
        data = _read(ser, seq, 0x00, 0, 0, reg, length)
        out[name] = {"len": len(data), "hex": data.hex(),
                     "strings": [s for s in ascii_strings(data) if s.strip()]}
    return out


def port_behaviour(ser, seq, port, depth=SCAN_DEPTH):
    """How this port answers, and whether its clamp value looks like a real card.

    Records the clamp answer and the head of the chain, then reports the one fact
    that separates the two controllers: does the clamp value appear BEFORE a block
    that differs from it (filler), or only at/after the end (last real card)?
    """
    clamp = _read(ser, seq, 0x01, port, CLAMP_IDX, RX_BLOCK, 256)
    clamp_geo, clamp_dig = parse_geometry(clamp), _digest(clamp)

    head = []
    for i in range(depth):
        data = _read(ser, seq, 0x01, port, i, RX_BLOCK, 256)
        geo = parse_geometry(data)
        head.append({"idx": i, "geometry": list(geo) if geo else None,
                     "digest": _digest(data) if geo else None,
                     "is_clamp": bool(geo) and _digest(data) == clamp_dig})
        if not geo and i >= 2 and not any(h["geometry"] for h in head[-3:]):
            break                                   # silent port, stop early

    seen_clamp_first = False
    verdict = "no clamp value (port answers nothing past the chain)"
    if clamp_dig and clamp_geo:
        differing = next((h for h in head if h["geometry"] and not h["is_clamp"]),
                         None)
        if differing is None:
            verdict = ("every sampled index equals the clamp - cannot tell a chain "
                       "of identical cards from an empty port by content alone")
        else:
            seen_clamp_first = any(h["is_clamp"] for h in head
                                   if h["idx"] < differing["idx"])
            verdict = ("FILLER: the clamp value appears before a real card, so it "
                       "means 'no card here'" if seen_clamp_first else
                       "LAST-CARD: the clamp value never precedes a real card")
    return {"port": port,
            "clamp": {"geometry": list(clamp_geo) if clamp_geo else None,
                      "digest": clamp_dig, "hex": clamp[:48].hex()},
            "head": head, "clamp_precedes_real_card": seen_clamp_first,
            "verdict": verdict}


def capture(ser, ports=4, depth=SCAN_DEPTH):
    seq = Seq()
    _read(ser, seq, 0x01, 0, 0, RX_BLOCK, 256)      # warm-up; first read is unreliable
    return {"card": identify_card(ser, seq),
            "ports": [port_behaviour(ser, seq, p, depth) for p in range(ports)]}


def describe(cap):
    lines = []
    for name in ("tx_id", "tx_nssd"):
        f = cap["card"][name]
        lines.append(f"  {name:8} {f['len']:4d} B  {hexdump(bytes.fromhex(f['hex']))}")
        if f["strings"]:
            lines.append(f"           strings: {', '.join(f['strings'][:8])}")
    lines.append("")
    for p in cap["ports"]:
        c = p["clamp"]
        geo = f"{c['geometry'][0]}x{c['geometry'][1]}" if c["geometry"] else "none"
        lines.append(f"  port {p['port']+1}: clamp@{CLAMP_IDX} {geo} {c['digest']}")
        shown = [h for h in p["head"] if h["geometry"]]
        if shown:
            head = ", ".join(f"{h['idx']}:{h['geometry'][0]}x{h['geometry'][1]}"
                             + ("*" if h["is_clamp"] else "") for h in shown[:10])
            lines.append(f"            head  {head}   (* = equals clamp)")
        else:
            lines.append("            head  nothing answered")
        lines.append(f"            {p['verdict']}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Capture NovaStar sending-card identity + clamp behaviour")
    default_port = "COM5" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=None)
    ap.add_argument("--ports", type=int, default=4)
    ap.add_argument("--depth", type=int, default=SCAN_DEPTH,
                    help=f"indices to sample per port (default {SCAN_DEPTH})")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable; this is the form to send back")
    ap.add_argument("--save", metavar="FILE", help="also write the JSON to FILE")
    args = ap.parse_args()

    from nova_bright import detect_baud, open_serial
    if args.baud:
        ser, baud = open_serial(args.port, args.baud), args.baud
    else:
        ser, baud = detect_baud(args.port)
        if ser is None:
            sys.exit(f"nothing answered on {args.port}")
    try:
        cap = capture(ser, args.ports, args.depth)
    finally:
        ser.close()
    cap["serial_port"], cap["baud"] = args.port, baud

    if args.json:
        print(json.dumps(cap, indent=2))
    else:
        print(f"== {args.port} @ {baud} ==")
        print(describe(cap))
        print("\n  Run this on one wall of EACH controller type and keep both "
              "outputs:\n  the tx_id/tx_nssd bytes are the fingerprint, the port "
              "verdicts say\n  which clamp behaviour that fingerprint goes with.")
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(cap, f, indent=2)
        print(f"\n  wrote {args.save}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
