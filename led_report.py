#!/usr/bin/env python3
"""led_report.py - run EVERY Fleet Monitor LED reading against whatever wall is on
this machine - NovaStar or Huidu - and print one summary of what worked, what
failed, and what does not apply to this setup.

It never changes what the wall displays. It sends read/probe frames (NovaStar
register reads; Huidu class-0x01 queries) and never a brightness write, so it is
safe to run on a live wall of either vendor.

One caveat, so the claim is exact: reading the NovaStar light sensor writes its
trigger register first (`003f000002 = 3c`) - that is how the sensor is sampled and
exactly what NovaLCT does. It does not touch brightness or configuration. The Huidu
path writes nothing at all. It needs no template (Huidu brightness is not readable
anyway) and HDset/MonitorSite must be CLOSED so the port is free.

Checks run, and when each applies:

    check                     NovaStar            Huidu
    ----------------------    ----------------    ---------------------------
    controller / link         detect + baud       detect + baud
    receiving-card count      scan ports x chain  probe card indices
    brightness (read back)    live register read  N/A - not readable (protocol)
    ambient light sensor      on-card lux sensor  standalone 0-254 sensor if
                                                   --sensor-port given, else N/A
                                                   (HD-Y1 runs ambient on-card)

Every line is marked [ OK ] worked, [FAIL] applies but did not read, or [ -- ]
not applicable to this vendor/setup (expected, not a problem).

    python led_report.py                          # auto-detect the wall
    python led_report.py --led-port COM5          # force the cards' port
    python led_report.py --sensor-port COM7       # also read a standalone Huidu sensor
    python led_report.py --ports 8 --max-idx 255  # bigger NovaStar rig
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LED_PROBE = os.path.join(HERE, "led_probe")
for _p in (LED_PROBE,
           os.path.join(LED_PROBE, "nova_probe_re"),
           os.path.join(LED_PROBE, "led_probe_re")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from led_control import NovaLink, HdLink   # noqa: E402
except Exception as e:                         # pragma: no cover
    sys.exit(f"cannot import led_control from {LED_PROBE}: {e}\n"
             f"  run this from the client/ folder of the deployment bundle.")

class _EchoPort(Exception):
    """Raised to skip the card scan when a port answers at every index."""


OK, FAIL, NA = "ok", "fail", "na"
_MARK = {OK: "[ OK ]", FAIL: "[FAIL]", NA: "[ -- ]"}


class Report:
    def __init__(self):
        self.rows = []          # (check, status, detail)

    def add(self, check, status, detail=""):
        self.rows.append((check, status, detail))

    def print(self):
        print("\n== LED reading summary ==")
        w = max(len(c) for c, _, _ in self.rows)
        for check, status, detail in self.rows:
            print(f"  {_MARK[status]}  {check.ljust(w)}   {detail}")
        n_ok = sum(1 for _, s, _ in self.rows if s == OK)
        n_na = sum(1 for _, s, _ in self.rows if s == NA)
        n_fail = sum(1 for _, s, _ in self.rows if s == FAIL)
        print(f"\n  {n_ok} read OK,  {n_na} not applicable,  {n_fail} failed")
        print("  [ OK ] worked   [ -- ] N/A for this setup   [FAIL] applies but "
              "did not read")


# --------------------------------------------------------------------------- #
# NovaStar
# --------------------------------------------------------------------------- #
def report_novastar(link, rep, args):
    rep.add("controller / link", OK, f"NovaStar on {link.port} @ {link.baud} 8N1")
    print(f"  · NovaStar on {link.port} @ {link.baud} - reading…", flush=True)
    ser, seq = link.ser, link.seq

    # sending-card ID (extra context; not a pass/fail feature)
    try:
        from nova_probe import build_read, transact, TX_ID, TX_NSSD, ascii_strings
        r = transact(ser, build_read(seq.next(), 0x00, 0, 0, TX_ID, 8))
        sid = r[0]["data"].hex() if r else None
        r = transact(ser, build_read(seq.next(), 0x00, 0, 0, TX_NSSD, 256))
        info = " | ".join(ascii_strings(r[0]["data"])) if r else ""
        rep.add("sending card", OK if sid else FAIL,
                (f"id {sid}" + (f"  {info}" if info else "")) if sid else "no reply")
    except Exception as e:
        rep.add("sending card", FAIL, str(e))

    # Per-PORT population, not a card count.
    #
    # An MCTRL600 answers EVERY index within a range with byte-identical data,
    # and returns the same block on different ports, so "walk indices until one
    # is absent" cannot count cards there - index 177 answers with valid
    # geometry on a wall with nowhere near 178 cards. What IS reliable is
    # whether a port has a populated chain at all: a used port returns valid
    # geometry, an unused one returns a block with none. That distinguishes live
    # ports from spare/redundancy ports, which is the question worth answering.
    try:
        from nova_probe import build_read, transact, RX_BLOCK, parse_geometry
        print(f"  · reading {args.ports} port(s)…", flush=True)
        live, empty, geoms = [], [], {}
        for p_i in range(args.ports):
            reps = transact(ser, build_read(seq.next(), 0x01, p_i, 0, RX_BLOCK, 256))
            geo = parse_geometry(reps[0]["data"] if reps else b"")
            if geo:
                live.append(p_i)
                geoms[p_i] = geo
            else:
                empty.append(p_i)
        if live:
            desc = ", ".join(f"port {p+1}: {geoms[p][0]}x{geoms[p][1]}" for p in live)
            extra = (f"; port(s) {', '.join(str(p+1) for p in empty)} unused"
                     if empty else "")
            rep.add("receiving-card ports", OK, f"{desc}{extra}")
        else:
            rep.add("receiving-card ports", FAIL,
                    "no port returned card geometry (panels off? cable?)")
        # Say plainly whether exact counts are obtainable on this controller.
        if live:
            far = transact(ser, build_read(seq.next(), 0x01, live[0],
                                           args.max_idx + 50, RX_BLOCK, 256))
            if parse_geometry(far[0]["data"] if far else b""):
                rep.add("per-card count", NA,
                        f"this controller answers out-of-range indices (index "
                        f"{args.max_idx + 50} returns geometry), so cards cannot be "
                        f"counted by walking indices - port population above is the "
                        f"reliable reading")
            else:
                from nova_bright import scan_brightness
                print("  · counting cards…", flush=True)
                cards = scan_brightness(ser, args.ports, args.max_idx, gap=args.gap)
                byport = {}
                for c in cards:
                    byport[c["port"]] = byport.get(c["port"], 0) + 1
                rep.add("per-card count", OK if cards else FAIL,
                        ", ".join(f"port {p+1}: {n}" for p, n in sorted(byport.items()))
                        or "none answered")
    except Exception as e:
        rep.add("receiving-card ports", FAIL, str(e))

    # brightness read-back (broadcast-global on NovaStar; read from a real card)
    try:
        pct, raw = link.read_brightness()
        if pct is not None:
            rep.add("brightness (read back)", OK, f"{pct}%  (raw {raw}/255)")
        else:
            rep.add("brightness (read back)", FAIL, "no value returned")
    except Exception as e:
        rep.add("brightness (read back)", FAIL, str(e))

    # ambient light sensor (on-card). valid flag distinguishes 'no sensor' from a
    # real reading; a missing sensor is N/A, not a failure.
    try:
        lux, valid = link.read_sensor()
        if valid and lux is not None:
            rep.add("ambient light sensor", OK, f"~{lux} lux")
        elif lux is None:
            rep.add("ambient light sensor", NA, "no light sensor attached to this card")
        else:
            rep.add("ambient light sensor", NA, "sensor reads as disconnected")
    except Exception as e:
        rep.add("ambient light sensor", FAIL, str(e))


# --------------------------------------------------------------------------- #
# Huidu
# --------------------------------------------------------------------------- #
def report_huidu(link, rep, args):
    rep.add("controller / link", OK, f"Huidu on {link.port} @ {link.baud} 8N1")
    ser = link.ser

    # receiving-card count via the read-only probe (class 0x01 only)
    try:
        from hd_bright import probe_fingerprint
        cards = probe_fingerprint(ser, max_cards=args.hd_cards)
        present = [c for c in cards if c.get("index") is not None]
        if present:
            geo = ", ".join(
                f"#{c['index']}: {c['width']}x{c['height']}"
                if c.get("width") else f"#{c['index']}"
                for c in present)
            rep.add("receiving-card count", OK, f"{len(present)} card(s)  ({geo})")
        else:
            rep.add("receiving-card count", FAIL,
                    f"no cards answered in indices 0..{args.hd_cards-1} "
                    f"(raise --hd-cards? panels off?)")
    except Exception as e:
        rep.add("receiving-card count", FAIL, str(e))

    # brightness read-back: a protocol limit, not a failure - the card ACKs a
    # write without echoing the level, so there is no read path.
    rep.add("brightness (read back)", NA,
            "not readable on Huidu - the card never echoes the level (protocol)")

    # ambient sensor: standalone unit on its own COM port, if configured. Walls
    # with an HD-Y1 have no such port and run ambient on-card -> N/A.
    if args.sensor_port:
        try:
            from hd_sensor import HdSensor
            import time
            s = HdSensor(args.sensor_port)
            if not s.open():
                rep.add("ambient light sensor", FAIL,
                        f"cannot open {args.sensor_port} (held by another program?)")
            else:
                light, valid, t0 = None, False, time.time()
                # the sensor emits only ~every 10s; wait up to --sensor-timeout
                while time.time() - t0 < args.sensor_timeout:
                    if s.poll() is not None:
                        light, valid = s.read_light()
                        break
                    time.sleep(0.2)
                s.close()
                if light is not None:
                    flag = "" if valid else "  (mid-ramp/stale - read again)"
                    rep.add("ambient light sensor", OK,
                            f"{light}/254 on {args.sensor_port}{flag}")
                else:
                    rep.add("ambient light sensor", FAIL,
                            f"no reading within {args.sensor_timeout:g}s on {args.sensor_port}")
        except Exception as e:
            rep.add("ambient light sensor", FAIL, str(e))
    else:
        rep.add("ambient light sensor", NA,
                "no --sensor-port given (HD-Y1 walls run ambient on-card)")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Run all Fleet Monitor LED readings and summarize (read-only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--led-port", default=None,
                    help="CP210x port of the cards (default: auto-detect)")
    ap.add_argument("--baud", type=int, default=None, help="serial baud (default: auto-detect)")
    ap.add_argument("--sensor-port", default=None,
                    help="Huidu standalone light-sensor COM port, if fitted")
    ap.add_argument("--sensor-timeout", type=float, default=15.0,
                    help="how long to wait for one Huidu sensor reading (~10s cadence)")
    ap.add_argument("--ports", type=int, default=8,
                    help="NovaStar: sending-card output ports to scan")
    ap.add_argument("--max-idx", type=int, default=127,
                    help="NovaStar: max receiving-card index per port (chain length cap)")
    ap.add_argument("--gap", type=int, default=3,
                    help="NovaStar: stop a port after this many consecutive missing cards")
    ap.add_argument("--hd-cards", type=int, default=8,
                    help="Huidu: how many card indices to probe")
    args = ap.parse_args()

    rep = Report()
    print("== detecting LED controller ==")

    nova = NovaLink(port=args.led_port, baud=args.baud)
    if nova.connect():
        try:
            report_novastar(nova, rep, args)
        finally:
            nova.close()
        rep.print()
        return 0

    hd = HdLink(port=args.led_port, baud=args.baud)
    if hd.probe_only():
        try:
            report_huidu(hd, rep, args)
        finally:
            hd.close()
        rep.print()
        return 0

    print("  no LED controller answered on "
          f"{args.led_port or 'any CP210x port'}.")
    print("  - is the sending card connected and powered?")
    print("  - is HDset / NovaLCT / MonitorSite holding the port? close it.")
    print("  - try --led-port and/or --baud explicitly.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
