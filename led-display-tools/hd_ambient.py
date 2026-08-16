#!/usr/bin/env python3
"""hd_ambient.py - SUPERSEDED by led_ambient.py, which does the same job for
NovaStar AND Huidu off the same engine (led_ambient_core). Kept only so existing
scripts calling it keep working; prefer led_ambient.py for anything new.

Self-contained ambient-brightness daemon for a Huidu wall whose
light sensor is a standalone unit on its OWN USB-serial COM port (the setup with
NO HD-Y1 multifunction card).

What it does, in one loop:
  1. reads the standalone light sensor (0-254, higher = brighter; see hd_sensor.py),
  2. maps that light level onto a brightness percent between --min-pct and --max-pct,
  3. writes the result to the receiving cards over the CP210x link (patch-and-replay
     of THIS wall's template; see hd_bright.py / PROTOCOL.md).

It reuses the exact, hardware-verified code the fleet client uses - HdLink for the
cards and the sensor, so behaviour matches the dashboard's Ambient mode - but runs
standalone, needs no server, and clamps brightness with a simple min/max map you
set on the command line instead of a dashboard curve.

  ** This is for the STANDALONE-SENSOR Huidu setup only. **
  Walls with an HD-Y1 run ambient in hardware - for those, don't run this; instead
  hand control to the card once with:  hd_bright.py --auto

Requirements:
  * the wall's own template (walls/<name>.bin), made by provision_wall.py. Never
    share a template between walls - it carries that wall's whole screen config.
  * the sensor's COM port, and the cards' CP210x port (auto-detected if omitted).
  * HDset must be CLOSED so the cards' port is free.

Examples:
    # dry run first - see the mapping react without writing to the wall
    python hd_ambient.py --sensor-port COM7 --template walls/wall_north.bin \
        --min-pct 15 --max-pct 90 --dry-run

    # live: sensor on COM7, cards auto-detected, hold 15..90 %
    python hd_ambient.py --sensor-port COM7 --template walls/wall_north.bin \
        --min-pct 15 --max-pct 90

    # tune the light window to THIS wall's dusk..day range first:
    python led_probe/led_probe_re/hd_sensor.py --port COM7 --log day.csv   # leave running
    python led_probe/led_probe_re/hd_sensor.py --summarize day.csv         # pick lo/hi
    python hd_ambient.py --sensor-port COM7 --template walls/wall_north.bin \
        --min-pct 15 --max-pct 90 --light-lo 20 --light-hi 210
"""
import argparse
import os
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
LED_PROBE = os.path.join(HERE, "led_probe")
# put led_probe and its two vendor dirs on the path so led_control + the Huidu
# modules import the same way they do inside the fleet client.
for _p in (LED_PROBE,
           os.path.join(LED_PROBE, "nova_probe_re"),
           os.path.join(LED_PROBE, "led_probe_re")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from led_control import HdLink            # noqa: E402
except Exception as e:                        # pragma: no cover - import guard
    sys.exit(f"cannot import led_control from {LED_PROBE}: {e}\n"
             f"  run this from the client/ folder of the deployment bundle.")


def brightness_for_light(light, min_pct, max_pct, light_lo, light_hi):
    """Clamped-linear map: light<=light_lo -> min_pct, light>=light_hi -> max_pct,
    straight line between. `light` is the sensor's 0-254 value (NOT lux). Returns
    an int percent, or None if `light` is None."""
    if light is None:
        return None
    if light_hi <= light_lo:
        return int(round(max_pct))
    f = (light - light_lo) / float(light_hi - light_lo)
    f = 0.0 if f < 0 else (1.0 if f > 1 else f)
    return int(round(min_pct + (max_pct - min_pct) * f))


def run(args):
    lo, hi = int(args.min_pct), int(args.max_pct)
    if hi < lo:
        lo, hi = hi, lo
    llo, lhi = int(args.light_lo), int(args.light_hi)

    link = HdLink(port=args.led_port, baud=args.baud,
                  template=args.template, sensor_port=args.sensor_port)

    print(f"== hd_ambient: Huidu standalone-sensor ambient loop ==")
    print(f"   sensor   : {args.sensor_port}  (0-254, higher = brighter)")
    print(f"   cards    : {args.led_port or 'auto-detect CP210x'}"
          f"   template: {args.template}")
    print(f"   map      : light {llo}->{lo}%  ..  {lhi}->{hi}%"
          f"   deadband: {args.deadband}%   every {args.interval:g}s")
    if args.fail_pct is not None:
        print(f"   sensor-fail after {args.fail_after}s -> {int(args.fail_pct)}%")
    if args.dry_run:
        print("   DRY RUN - reading the sensor and computing only, NOT writing to the wall")

    # Connect to the cards up front (unless dry-run, which never writes) so a bad
    # template / wrong wall / busy port is reported immediately, not on first dusk.
    if not args.dry_run:
        if not link.connect():
            sys.exit("  cannot reach the wall's cards - check the CP210x cable/port, "
                     "the template, and that HDset is closed.\n"
                     "  (a template recorded for a DIFFERENT wall is refused on purpose)")
        print(f"   connected to cards on {link.port} @ {link.baud}")

    last_set = None
    last_valid_t = time.time()
    failed_applied = False
    try:
        while True:
            light, valid = link.read_sensor()
            now = datetime.now().strftime("%H:%M:%S")

            if valid and light is not None:
                last_valid_t = time.time()
                failed_applied = False
                target = brightness_for_light(light, lo, hi, llo, lhi)
                change = last_set is None or abs(target - last_set) >= args.deadband
                tag = "" if change else "  (within deadband, hold)"
                print(f"  {now}  light={light:3d}/254 -> target {target:3d}%{tag}")
                if change:
                    if args.dry_run:
                        last_set = target
                    else:
                        applied = link.set_brightness(target)
                        if applied is None:
                            print(f"           ! no ACK from the cards - will retry")
                        else:
                            last_set = applied
            else:
                stale_for = time.time() - last_valid_t
                print(f"  {now}  sensor not ready (mid-ramp or stale, {stale_for:.0f}s)")
                if (args.fail_pct is not None and stale_for >= args.fail_after
                        and not failed_applied):
                    fp = int(args.fail_pct)
                    print(f"           sensor failed -> falling back to {fp}%")
                    if not args.dry_run:
                        if link.set_brightness(fp) is not None:
                            last_set, failed_applied = fp, True
                    else:
                        last_set, failed_applied = fp, True

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n  stopped.")
    finally:
        if not args.dry_run:
            link.close()
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Ambient brightness for a Huidu wall with a standalone light sensor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--sensor-port", required=True,
                    help="COM port of the standalone light sensor (its own USB-serial)")
    ap.add_argument("--template", required=True,
                    help="this wall's brightness template (walls/<name>.bin) - never shared")
    ap.add_argument("--led-port", default=None,
                    help="CP210x port of the receiving cards (default: auto-detect)")
    ap.add_argument("--baud", type=int, default=None,
                    help="cards' serial baud (default: auto-detect)")
    ap.add_argument("--min-pct", type=float, default=15,
                    help="brightness at/below --light-lo (the wall never dips below this)")
    ap.add_argument("--max-pct", type=float, default=90,
                    help="brightness at/above --light-hi (the wall never exceeds this)")
    ap.add_argument("--light-lo", type=int, default=0,
                    help="sensor light value that maps to --min-pct (dark end)")
    ap.add_argument("--light-hi", type=int, default=254,
                    help="sensor light value that maps to --max-pct (bright end)")
    ap.add_argument("--deadband", type=int, default=2,
                    help="only rewrite the wall when the target moves at least this many %%")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="loop period in seconds (the sensor updates ~every 10s)")
    ap.add_argument("--fail-pct", type=float, default=None,
                    help="if the sensor goes quiet, hold this %% (default: keep last value)")
    ap.add_argument("--fail-after", type=float, default=120.0,
                    help="seconds without a valid reading before --fail-pct kicks in")
    ap.add_argument("--dry-run", action="store_true",
                    help="read + compute only; never write to the wall")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
