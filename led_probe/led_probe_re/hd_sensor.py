#!/usr/bin/env python3
"""hd_sensor.py - read the standalone Huidu light sensor (the type used on systems
with NO multifunction card) from its own USB-serial COM port.

Wire format (see PROTOCOL.md), streamed continuously at 9600 baud, ~1 record per
10 s, nothing needs to poll it:

    C9 "S01" "P7D" "V0E2" "v0E2" \\r\\n

`P` is the reading, 8-bit, and it is **INVERTED - it measures darkness**:

    P =   1   direct torch light
    P =  17   ordinary indoor ambient
    P = 255   fully covered (saturated)

so brightness must be derived from (255 - P). Verified over two full
cover/uncover cycles, each held to a settled plateau.

Two properties that shape how this must be used:
  * SLOW - one reading per ~10 s.
  * SLEW-LIMITED - during a large change the value ramps at a dead-constant
    ~30 units per reading (~3/s) in both directions, so a full-range swing takes
    ~80 s to be reported. It is a ramp toward the true level, not the level
    itself. Do not treat a mid-ramp sample as a light measurement, and do not
    build a control loop that reacts faster than the sensor can report.

    python hd_sensor.py --port /dev/ttyACM1            # follow the reading
    python hd_sensor.py --port COM7 --once             # one reading, for scripts
"""
import argparse
import os
import sys
import time

DEFAULT_BAUD = 9600
RECORD_MARKER = 0xC9

# Calibration anchors, measured on real hardware (settled plateaus).
RAW_BRIGHT = 1      # torch directly on the sensor
RAW_AMBIENT = 17    # ordinary indoor light
RAW_DARK = 255      # covered; the 8-bit ceiling, so "dark" saturates here

# A large change ramps at ~30 raw units per ~10s reading. Used to spot samples
# taken mid-ramp, which are not yet the real light level.
SLEW_PER_READING = 30


def light_from_raw(raw):
    """Inverted reading -> 0..254 where higher means brighter.

    NOT lux. The NovaStar sensor reports lux and the HD-Y1's reports a value that
    rises with light; this one falls with light. Curves written for those walls do
    not transfer - author Huidu-standalone curves in these units."""
    if raw is None:
        return None
    return max(0, min(254, 255 - int(raw)))


def parse_record(rec):
    """b'\\xc9S01P7DV0E2v0E2' -> {'S':1,'P':125,'V':226,'v':226}, or {}."""
    import re
    out = {}
    for m in re.finditer(rb"([A-Za-z])([0-9A-Fa-f]+)", bytes(rec)):
        try:
            out[m.group(1).decode()] = int(m.group(2), 16)
        except ValueError:
            pass
    return out


def split_records(buf):
    """(complete records, remainder). The stream is CR/LF delimited."""
    parts = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    return [p for p in parts[:-1] if p], parts[-1]


class HdSensor:
    """Holds the sensor port open and reports the most recent reading.

    Non-blocking by design: `poll()` drains whatever has arrived and returns the
    newest value, or None if nothing new. Because the sensor emits only every
    ~10 s, callers should use `last`/`age` rather than expecting a value on
    demand. Soft-fails throughout - never raises at the caller."""

    def __init__(self, port, baud=DEFAULT_BAUD):
        self.port = port
        self.baud = baud
        self.ser = None
        self.buf = b""
        self.last_raw = None
        self.last_t = None
        self.prev_raw = None

    def open(self):
        try:
            import serial
        except ImportError:
            return False
        p = self.port
        if sys.platform == "win32" and p.upper().startswith("COM"):
            p = f"\\\\.\\{p}"
        try:
            self.ser = serial.Serial(p, self.baud, timeout=0)
        except Exception:
            self.ser = None
            return False
        return True

    def ensure(self):
        return True if self.ser is not None else self.open()

    def close(self):
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def poll(self):
        """Drain the port; return the newest raw P seen, or None."""
        if not self.ensure():
            return None
        try:
            self.buf += self.ser.read(4096)
        except Exception:
            self.close()
            return None
        recs, self.buf = split_records(self.buf)
        newest = None
        for rec in recs:
            f = parse_record(rec)
            if "P" in f:
                newest = f["P"]
        if newest is not None:
            self.prev_raw, self.last_raw = self.last_raw, newest
            self.last_t = time.time()
        return newest

    @property
    def age(self):
        """Seconds since the last reading, or None."""
        return None if self.last_t is None else time.time() - self.last_t

    def ramping(self):
        """True if the last two readings differ by about a full slew step - i.e.
        the value is mid-ramp and does not yet reflect the real light level."""
        if self.last_raw is None or self.prev_raw is None:
            return False
        return abs(self.last_raw - self.prev_raw) >= SLEW_PER_READING - 5

    def read_light(self, max_age=45.0):
        """(light, valid) with light 0..254, higher = brighter.

        `valid` is False when we have no reading, when the newest is older than
        `max_age` (default ~4 update intervals), or while the value is still
        ramping - a mid-ramp sample is not a light measurement."""
        self.poll()
        if self.last_raw is None:
            return (None, False)
        stale = self.age is not None and self.age > max_age
        return (light_from_raw(self.last_raw), not (stale or self.ramping()))


def log_to_csv(sensor, path, echo=True):
    """Append timestamped readings until interrupted.

    Built for long unattended runs - an outdoor wall's useful range is the dusk
    transition, which spot readings cannot capture. Leave this running from
    afternoon into night and the whole curve is in the file. Each line is flushed
    and the port is reopened if it drops, so a several-hour run survives a glitch.
    """
    import datetime
    new = not os.path.exists(path)
    t0 = time.time()
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("iso_time,elapsed_s,raw_p,light,valid\n")
            f.flush()
        while True:
            if sensor.poll() is not None:
                light, valid = sensor.read_light()
                iso = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
                f.write(f"{iso},{time.time()-t0:.0f},{sensor.last_raw},"
                        f"{light},{int(bool(valid))}\n")
                f.flush()
                if echo:
                    flag = "" if valid else ("  (ramping)" if sensor.ramping()
                                             else "  (stale)")
                    print(f"  {iso}  raw P={sensor.last_raw:3d}  "
                          f"light={light:3d}/254{flag}")
            time.sleep(0.5)


def summarize_csv(path):
    """Report the range and the shape of the day from a logged run - the numbers
    needed to author an ambient curve in this sensor's units."""
    import csv as _csv
    rows = []
    with open(path, encoding="utf-8") as f:
        for r in _csv.DictReader(f):
            try:
                rows.append((r["iso_time"], int(r["raw_p"]), int(r["light"]),
                             r["valid"] == "1"))
            except (KeyError, ValueError):
                continue
    if not rows:
        sys.exit(f"{path}: no readings")
    good = [r for r in rows if r[3]] or rows
    raws = [r[1] for r in good]
    print(f"== {path}: {len(rows)} readings ({len(good)} settled) ==")
    print(f"  raw P : {min(raws)} .. {max(raws)}      "
          f"(1=brightest seen, 255=dark ceiling)")
    print(f"  light : {255-max(raws)} .. {255-min(raws)} /254\n")
    print("  by hour (median raw P, and light):")
    byhour = {}
    for iso, raw, light, _v in good:
        byhour.setdefault(iso[:13], []).append(raw)
    for hour in sorted(byhour):
        vals = sorted(byhour[hour])
        med = vals[len(vals) // 2]
        bar = "#" * max(1, int(light_from_raw(med) / 254 * 40))
        print(f"    {hour}  P={med:3d}  light={light_from_raw(med):3d}  {bar}")
    print("\n  Author the curve in LIGHT units (higher = brighter), not lux.")
    if min(raws) <= 1:
        print("  NOTE: raw P bottomed out at <=1 - the sensor SATURATES in")
        print("  daylight, so bright sun and dull overcast read the same. Treat")
        print("  everything at the bright end as one 'daytime' step; the useful")
        print("  resolution is the dusk-to-night range.")


def main():
    ap = argparse.ArgumentParser(description="Read the standalone Huidu light sensor")
    default_port = "COM7" if sys.platform == "win32" else "/dev/ttyACM1"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--once", action="store_true",
                    help="wait for one reading, print it, exit")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="how long --once waits (the sensor emits every ~10s)")
    ap.add_argument("--log", metavar="CSV",
                    help="append timestamped readings to a CSV; leave running "
                         "across dusk to capture the real outdoor range")
    ap.add_argument("--summarize", metavar="CSV",
                    help="report the range and shape of the day from a log")
    args = ap.parse_args()

    if args.summarize:
        summarize_csv(args.summarize)
        return 0

    s = HdSensor(args.port, args.baud)
    if not s.open():
        sys.exit(f"cannot open {args.port} (is another program holding it?)")
    if args.log:
        print(f"== logging {args.port} -> {args.log} (Ctrl-C to stop) ==")
        try:
            log_to_csv(s, args.log)
        except KeyboardInterrupt:
            print("\n  stopped; summarize with: "
                  f"hd_sensor.py --summarize {args.log}")
        finally:
            s.close()
        return 0
    try:
        if args.once:
            t0 = time.time()
            while time.time() - t0 < args.timeout:
                if s.poll() is not None:
                    light, valid = s.read_light()
                    print(f"raw P={s.last_raw}  light={light}/254  valid={valid}")
                    return 0
                time.sleep(0.2)
            print("no reading within timeout")
            return 1
        print(f"== {args.port} @ {args.baud} - Ctrl-C to stop ==")
        print(f"   raw P is INVERTED: {RAW_BRIGHT}=torch  {RAW_AMBIENT}=ambient  "
              f"{RAW_DARK}=covered\n")
        while True:
            if s.poll() is not None:
                light, valid = s.read_light()
                flag = "" if valid else ("  (ramping)" if s.ramping() else "  (stale)")
                print(f"  raw P={s.last_raw:3d}   light={light:3d}/254{flag}")
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
