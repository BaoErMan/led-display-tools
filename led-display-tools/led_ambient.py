#!/usr/bin/env python3
"""led_ambient.py - drive an LED wall's brightness from a STANDALONE light sensor,
for NovaStar OR Huidu. The vendor-agnostic successor to hd_ambient.py.

It reads the 8-bit sensor on its own COM port (0-254, higher = brighter), maps it
between --min-pct and --max-pct, and writes brightness to whichever controller is
on --led-port. NovaStar needs no template; Huidu needs this wall's --template.

    # NovaStar wall, sensor on COM7, controller auto-detected
    python led_ambient.py --sensor-port COM7 --min-pct 15 --max-pct 90

    # Huidu wall (template required), watch it react first without writing
    python led_ambient.py --sensor-port COM7 --vendor huidu \
        --template walls/wall_north.bin --min-pct 15 --max-pct 90 --dry-run

Tune the light window to the wall's real dusk->day range first with
    led_probe/led_probe_re/hd_sensor.py --port COM7 --log day.csv   # leave running
    led_probe/led_probe_re/hd_sensor.py --summarize day.csv         # pick lo/hi
then pass --light-lo/--light-hi.

A GUI version (Windows + Linux) is in led_ambient_gui.py.
"""
import argparse
import sys
import time

from led_ambient_core import AmbientController


def run(args):
    ctl = AmbientController(
        sensor_port=args.sensor_port, led_port=args.led_port, baud=args.baud,
        vendor=args.vendor, template=args.template,
        min_pct=args.min_pct, max_pct=args.max_pct,
        light_lo=args.light_lo, light_hi=args.light_hi,
        deadband=args.deadband, fail_pct=args.fail_pct, fail_after=args.fail_after,
        dry_run=args.dry_run)

    lo, hi = int(min(args.min_pct, args.max_pct)), int(max(args.min_pct, args.max_pct))
    print("== led_ambient: standalone sensor -> LED brightness ==")
    print(f"   sensor : {args.sensor_port}  (0-254, higher = brighter)")
    print(f"   ctrl   : {args.led_port or 'auto-detect'}  vendor={args.vendor}"
          + (f"  template={args.template}" if args.template else ""))
    print(f"   map    : light {args.light_lo}->{lo}%  ..  {args.light_hi}->{hi}%"
          f"   deadband {args.deadband}%   every {args.interval:g}s")
    if args.dry_run:
        print("   DRY RUN - computing only, NOT writing to the wall")

    ok, msg = ctl.connect()
    if not ok and not args.dry_run:
        sys.exit(f"  {msg}")
    # In dry-run we still want to try, but tolerate a missing controller so you can
    # watch the sensor map alone. Report either way.
    print(f"   {'connected: ' if ok else 'NOT connected: '}{msg}")
    if not ok:
        return 1

    try:
        while True:
            st = ctl.step()
            line = f"  {st['t']}  "
            if st["light"] is not None:
                line += f"light={st['light']:3d}/254 -> target {st['target']:3d}%"
                if st["applied"] is not None:
                    line += f"  set {st['applied']}%"
            else:
                line += "sensor --"
            if st["note"]:
                line += f"   ({st['note']})"
            print(line)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n  stopped.")
    finally:
        ctl.close()
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Ambient brightness from a standalone sensor (NovaStar or Huidu)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--sensor-port", required=True,
                    help="COM port of the standalone light sensor")
    ap.add_argument("--vendor", choices=("auto", "novastar", "huidu"), default="auto",
                    help="LED controller family (auto = detect NovaStar then Huidu)")
    ap.add_argument("--template", default=None,
                    help="Huidu only: this wall's brightness template (walls/<name>.bin)")
    ap.add_argument("--led-port", default=None,
                    help="controller's CP210x port (default: auto-detect)")
    ap.add_argument("--baud", type=int, default=None, help="controller baud (default: auto)")
    ap.add_argument("--min-pct", type=float, default=15,
                    help="brightness at/below --light-lo")
    ap.add_argument("--max-pct", type=float, default=90,
                    help="brightness at/above --light-hi")
    ap.add_argument("--light-lo", type=int, default=0, help="sensor value mapping to --min-pct")
    ap.add_argument("--light-hi", type=int, default=254, help="sensor value mapping to --max-pct")
    ap.add_argument("--deadband", type=int, default=2,
                    help="only rewrite when the target moves at least this many %%")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="loop period in seconds (the sensor updates ~every 10s)")
    ap.add_argument("--fail-pct", type=float, default=None,
                    help="hold this %% if the sensor goes quiet (default: keep last)")
    ap.add_argument("--fail-after", type=float, default=120.0,
                    help="seconds without a valid reading before --fail-pct applies")
    ap.add_argument("--dry-run", action="store_true", help="read + compute only, never write")
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
