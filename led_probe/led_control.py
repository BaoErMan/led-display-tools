#!/usr/bin/env python3
"""led_control.py - persistent NovaStar link for the Fleet Monitor client's
brightness CONTROL loop (manual hold / ambient sensor-driven).

Only used when the client runs with --nova-control. The client becomes the SOLE
brightness controller for that NovaStar wall (MonitorSite must be off so the port
is free). NovaLink owns one CP210x serial connection - detecting baud once - and
exposes read_brightness / read_sensor / set_brightness on it, reconnecting if the
port drops (e.g. an operator grabs it in NovaLCT). NovaStar-only and every method
soft-fails to None / False instead of raising.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
# nova_probe_re / led_probe_re sit beside this file once deployed, but are
# siblings of runtime/ in the research bundle - accept either layout.
_VENDOR_DIRS = [os.path.join(base, sub)
                for base in (_HERE, _PARENT)
                for sub in ("nova_probe_re", "led_probe_re")]
for _p in [_HERE, _PARENT] + _VENDOR_DIRS:
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

# reuse the read-only probe's port/baud helpers (same CP210x detection + cache)
from led_brightness import _cp210x_ports, _open, BAUD_CANDIDATES, _good_baud  # noqa: E402


def brightness_for_lux(lux, min_pct=20, max_pct=100, lux_low=10, lux_high=800):
    """Clamped-linear ambient curve: lux<=lux_low -> min_pct, lux>=lux_high ->
    max_pct, linear between. Returns an int percent, or None if lux is None."""
    if lux is None:
        return None
    if lux_high <= lux_low:
        return max_pct
    f = (lux - lux_low) / float(lux_high - lux_low)
    f = 0.0 if f < 0 else (1.0 if f > 1 else f)
    return int(round(min_pct + (max_pct - min_pct) * f))


def default_curve(lux_lo=20, pct_lo=20, lux_hi=12000, pct_hi=80, n=20):
    """NovaLCT-style ambient curve: `n` points from (lux_lo,pct_lo) to
    (lux_hi,pct_hi), evenly spaced in lux (a straight line you can then bend by
    editing individual points)."""
    pts = []
    for i in range(n):
        f = i / (n - 1)
        pts.append([round(lux_lo + (lux_hi - lux_lo) * f),
                    round(pct_lo + (pct_hi - pct_lo) * f)])
    return pts


def curve_pct(lux, points):
    """Piecewise-linear interpolate brightness% for `lux` over [[lux,pct],...],
    clamped flat beyond the first/last point. None if no points."""
    if not points:
        return None
    pts = sorted(points, key=lambda p: p[0])
    if lux <= pts[0][0]:
        return int(round(pts[0][1]))
    if lux >= pts[-1][0]:
        return int(round(pts[-1][1]))
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if x0 <= lux <= x1:
            if x1 == x0:
                return int(round(y0))
            f = (lux - x0) / (x1 - x0)
            return int(round(y0 + (y1 - y0) * f))
    return int(round(pts[-1][1]))


def _hhmm(s):
    h, m = str(s).split(":")
    return int(h) * 60 + int(m)


def active_cap(now, caps):
    """Lowest max_pct among time caps active at `now` (a UTC datetime), or None.
    Each cap = {"from":"HH:MM","to":"HH:MM","max_pct":N}; windows wrap midnight."""
    cur = now.hour * 60 + now.minute
    best = None
    for c in caps or []:
        try:
            a, b, cap = _hhmm(c["from"]), _hhmm(c["to"]), int(c["max_pct"])
        except Exception:
            continue
        if a == b:
            continue                     # empty window
        active = (a <= cur < b) if a < b else (cur >= a or cur < b)
        if active:
            best = cap if best is None else min(best, cap)
    return best


def compute_target(cfg, mode, manual_pct, lux, sensor_valid, now):
    """Final 0-100 target for a config dict, or None to hold. manual -> manual_pct;
    ambient -> curve(lux) or sensor_fail_pct; then apply any active time cap.
    `now` is a UTC datetime."""
    c = cfg or {}
    if mode == "manual":
        t = manual_pct
    elif sensor_valid:
        t = curve_pct(lux, c.get("curve") or [])
    else:
        t = c.get("sensor_fail_pct")
    if t is None:
        return None
    cap = active_cap(now, c.get("time_caps"))
    if cap is not None:
        t = min(t, cap)
    return int(max(0, min(100, round(t))))


def _pretty(cfg):
    """Serialize config with one [lux, pct] per line so the curve is easy to edit
    (only used for the initial auto-created file; user edits are read as-is)."""
    import json
    out = ["{"]
    if "_help" in cfg:
        out.append('  "_help": ' + json.dumps(cfg["_help"]) + ",")
    out.append('  "curve": [')
    curve = cfg.get("curve", [])
    for i, pt in enumerate(curve):
        sep = "," if i < len(curve) - 1 else ""
        out.append(f"    [{int(pt[0])}, {int(pt[1])}]{sep}")
    out.append("  ],")
    out.append('  "sensor_fail_pct": ' + json.dumps(cfg.get("sensor_fail_pct")) + ",")
    out.append('  "time_caps": ' + json.dumps(cfg.get("time_caps", [])) + ",")
    out.append('  "amb_min": ' + json.dumps(cfg.get("amb_min", 20)) + ",")
    out.append('  "amb_max": ' + json.dumps(cfg.get("amb_max", 90)) + ",")
    out.append('  "light_lo": ' + json.dumps(cfg.get("light_lo", 0)) + ",")
    out.append('  "light_hi": ' + json.dumps(cfg.get("light_hi", 254)))
    out.append("}")
    return "\n".join(out) + "\n"


def pct_from_light(light, min_pct, max_pct, light_lo=0, light_hi=254):
    """Clamped-linear map of a standalone Huidu sensor value onto
    [min_pct, max_pct]: light<=light_lo -> min_pct, light>=light_hi -> max_pct.

    light_lo/light_hi MATTER. A real outdoor wall does not use the full 0-254
    span: a measured 24h profile ran ~30 at night to ~252 in daylight, so the
    default 0..254 leaves the wall at ~28% overnight and it never reaches
    min_pct. Log a day with hd_sensor.py --log / --summarize and set these to the
    wall's own settled night/day values."""
    if light is None:
        return None
    lo, hi = (min_pct, max_pct) if max_pct >= min_pct else (max_pct, min_pct)
    llo, lhi = int(light_lo), int(light_hi)
    if lhi <= llo:
        return int(round(hi))
    f = max(0.0, min(1.0, (light - llo) / float(lhi - llo)))
    return int(round(lo + (hi - lo) * f))


class LedConfig:
    """Ambient config loaded from a JSON file (auto-created with sane defaults,
    hot-reloaded when the file changes). Computes the final brightness target,
    applying the curve / sensor-fail default and any active time cap."""

    def __init__(self, path):
        self.path = path
        self.mtime = None
        self.cfg = None
        self.load()

    def defaults(self):
        return {
            "_help": ("curve: [[lux,pct],...] piecewise-linear, clamped at the ends. "
                      "sensor_fail_pct: brightness used when the light sensor is "
                      "unavailable. time_caps: [{from,to,max_pct}] hard ceiling by "
                      "time of day (UTC, HH:MM, wraps midnight; applies in manual "
                      "AND ambient) - NONE by default; see led_config.example.json "
                      "for the format. This file hot-reloads within ~5s of a save."),
            "curve": default_curve(),
            "sensor_fail_pct": 30,
            "time_caps": [],
            # Ambient min/max brightness range. Used by BOTH Huidu ambient paths:
            # HD-Y1 (the card's on-card loop is clamped to this) and a standalone
            # 0-254 sensor (light is mapped linearly across this range). NovaStar
            # ambient uses the curve above, not this.
            "amb_min": 20,
            "amb_max": 90,
            # standalone Huidu sensor only: the wall's own dark/bright values.
            "light_lo": 0,
            "light_hi": 254,
        }

    def load(self):
        import json
        try:
            with open(self.path, encoding="utf-8") as f:
                self.cfg = json.load(f)
            self.mtime = os.path.getmtime(self.path)
        except FileNotFoundError:
            self.cfg = self.defaults()
            self._write()
        except Exception as e:
            if self.cfg is None:
                self.cfg = self.defaults()
            print(f"  · led_config.json invalid ({e}); keeping previous/defaults")

    def _write(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                f.write(_pretty(self.cfg))
            self.mtime = os.path.getmtime(self.path)
            print(f"  · wrote default led_config.json -> {self.path}")
        except Exception as e:
            print(f"  · could not write led_config.json: {e}")

    def maybe_reload(self):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return
        if m != self.mtime:
            print("  · led_config.json changed; reloading")
            self.load()

    def target(self, mode, manual_pct, lux, sensor_valid, now):
        """Final 0-100 target, or None to hold. `now` is a UTC datetime."""
        return compute_target(self.cfg, mode, manual_pct, lux, sensor_valid, now)


class NovaLink:
    """One persistent, auto-baud NovaStar serial connection. Soft-fails."""

    def __init__(self, port=None, baud=None):
        self._port_arg = port
        self._baud_arg = baud
        self.ser = None
        self.seq = None
        self.port = None
        self.baud = None
        self.card = None   # (port, idx) of a real receiving card, found once

    def _candidates(self):
        return [self._port_arg] if self._port_arg else _cp210x_ports()

    def connect(self):
        """Open the first CP210x port that answers as NovaStar; detect baud."""
        try:
            import serial  # noqa: F401
            from nova_probe import Seq, build_read, transact, TX_ID, RX_BLOCK
        except (Exception, SystemExit):
            return False
        for p in self._candidates():
            if self._baud_arg:
                bauds = [self._baud_arg]
            else:
                bauds = list(dict.fromkeys(
                    ([_good_baud[p]] if p in _good_baud else []) + list(BAUD_CANDIDATES)))
            for b in bauds:
                try:
                    ser = _open(p, b)
                except Exception:
                    continue
                try:
                    seq = Seq()
                    # Probe with a 256-byte card read, not the 8-byte ID: short
                    # reads survive a 4.63% baud mismatch (1000000 vs an
                    # MCTRL600's 1048576), so an ID-only probe happily settles on
                    # a rate where every large reply is then corrupt. Fall back to
                    # the ID read only if no card answers anywhere - some walls
                    # have unreadable cards but a responsive sending card.
                    # retries=0: a retry here only slows down rates that are
                    # wrong anyway, and detection must stay quick.
                    ok = False
                    for _pt in (0, 1):
                        r = transact(ser, build_read(seq.next(), 0x01, _pt, 0,
                                                     RX_BLOCK, 256), retries=0)
                        if r and len(r[0]["data"]) >= 256:
                            ok = True
                            break
                    if not ok:
                        ok = bool(transact(ser, build_read(seq.next(), 0x00, 0, 0,
                                                           TX_ID, 8), retries=0))
                    if ok:
                        self.ser, self.seq, self.port, self.baud = ser, seq, p, b
                        self.card = None      # re-find the real card on this link
                        _good_baud[p] = b
                        return True
                except Exception:
                    pass
                try:
                    ser.close()
                except Exception:
                    pass
        return False

    def ensure(self):
        return True if self.ser is not None else self.connect()

    def close(self):
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def read_brightness(self):
        """(pct, raw) of the wall from a real card, or (None, None)."""
        if not self.ensure():
            return (None, None)
        try:
            from nova_bright import read_brightness as _rb, raw_to_pct
            from led_brightness import find_card
            if self.card is None:
                self.card = find_card(self.ser, self.seq)   # cards may be on port 1/2
            p, i = self.card
            raw = _rb(self.ser, p, i, self.seq)
            if raw is None:
                self.card = None            # re-find next time
                return (None, None)
            return (int(raw_to_pct(raw)), int(raw))
        except Exception:
            self.close()
            return (None, None)

    def read_sensor(self):
        """(lux, valid) of the ambient light sensor, or (None, False)."""
        if not self.ensure():
            return (None, False)
        try:
            from nova_sensor import read_sensor, decode
            v = read_sensor(self.ser, self.seq, trigger=True)
            if not v:
                return (None, False)
            d = decode(v)
            return (d["lux"], d["valid"])
        except Exception:
            self.close()
            return (None, False)

    def set_brightness(self, pct):
        """Broadcast a level to the whole wall. Returns the applied percent or None."""
        if not self.ensure():
            return None
        try:
            from nova_bright import set_brightness, pct_to_raw, raw_to_pct
            raw = pct_to_raw(pct)
            set_brightness(self.ser, raw, self.seq)
            return int(raw_to_pct(raw))
        except Exception:
            self.close()
            return None


class HdLink:
    """One persistent Huidu (HDset) serial connection. Same soft-fail contract as
    NovaLink: every method returns None/False rather than raising.

    Brightness is sent as a patched replay of a class-0x02 config block captured
    from THIS wall (see led_probe_re/PROTOCOL.md), so a template is required and
    is NOT interchangeable between walls - it carries that wall's whole screen
    configuration.

    Two things differ from NovaLink, both protocol limits rather than choices:
      * brightness cannot be read back (the card ACKs without echoing it), so
        read_brightness reports the last value WE set;
      * ambient works differently per architecture. An HD-Y1 wall runs the loop
        ON THE CARD - use set_auto(True) plus set_auto_range(min, max); it reports
        no sensor, so read_sensor is (None, False). A wall with a STANDALONE
        sensor has no HD-Y1: pass sensor_port and read_sensor returns a real
        0-254 value (higher = brighter, NOT lux), so a NovaStar lux curve does
        not transfer.
    """

    def __init__(self, port=None, baud=None, template=None, sensor_port=None,
                 auto_template=None):
        self._port_arg = port
        self._baud_arg = baud
        self._template_arg = template
        self.ser = None
        self.port = None
        self.baud = None
        self.template = None
        self.last_set_pct = None      # what we last commanded; see read_brightness
        # The standalone light sensor is a SEPARATE USB-serial device, not this
        # link - walls with an HD-Y1 have no such port and leave this None.
        self.sensor_port = sensor_port
        self._sensor = None
        # A SECOND, different per-wall block: the HD-Y1 multifunction card's
        # ambient min/max clamp. Only needed to steer an HD-Y1 ambient wall.
        self.auto_template = auto_template

    def _candidates(self):
        return [self._port_arg] if self._port_arg else _cp210x_ports()

    def _load_template(self):
        from hd_bright import load_template, DEFAULT_TEMPLATE
        return load_template(self._template_arg or DEFAULT_TEMPLATE)

    def probe_only(self):
        """Open the first CP210x port that answers with a valid Huidu frame,
        WITHOUT needing a template. Setup uses this to identify the vendor before
        a template exists; `connect` adds the template on top."""
        try:
            import serial  # noqa: F401
            from hd_probe import build_frame, deframe, make_probe_payload
            from hd_bright import read_reply
        except (Exception, SystemExit):
            return False
        for p in self._candidates():
            bauds = [self._baud_arg] if self._baud_arg else list(BAUD_CANDIDATES)
            for b in bauds:
                try:
                    ser = _open(p, b)
                except Exception:
                    continue
                try:
                    ser.reset_input_buffer()
                    ser.write(build_frame(make_probe_payload(0)))
                    ser.flush()
                    if any(True for _f in deframe(read_reply(ser))):
                        self.ser, self.port, self.baud = ser, p, b
                        return True
                except Exception:
                    pass
                try:
                    ser.close()
                except Exception:
                    pass
        return False

    def connect(self):
        """Probe the link, load this wall's template, and verify the template
        actually belongs to this wall. Fails if any step does.

        The fingerprint check is not paranoia: two walls' blocks were compared and
        7 bytes of per-wall display geometry differ outside the brightness field,
        so a template from the wrong wall would rewrite that wall's screen
        configuration. If no fingerprint was recorded the check passes (there is
        nothing to compare against) - record one with `--save-fingerprint`."""
        if not self.probe_only():
            return False
        try:
            self.template = self._load_template()
        except (Exception, SystemExit):
            self.close()
            return False
        try:
            from hd_bright import check_fingerprint, DEFAULT_TEMPLATE
            path = self._template_arg or DEFAULT_TEMPLATE
            ok, expected, actual = check_fingerprint(self.ser, path)
            if not ok:
                print("  · REFUSING this template: it was recorded for a "
                      "different wall")
                print(f"      template expects {expected}")
                print(f"      this wall is     {actual}")
                print("    Provision this wall's own template - see README.")
                self.template = None
                self.close()
                return False
        except Exception:
            pass                      # verification is best-effort, never fatal
        return True

    def ensure(self):
        return True if self.ser is not None else self.connect()

    def close(self):
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        # The standalone light sensor is a SECOND serial port, so closing the
        # card link alone would leave it held - which blocks anything that
        # reopens the sensor (a restarted ambient loop, led_report.py).
        if self._sensor is not None:
            try:
                self._sensor.close()
            except Exception:
                pass
            self._sensor = None

    def read_brightness(self):
        """(pct, raw) - REPORTED, NOT READ BACK: what we last set, None until we
        set something.

        This is permanent, not a stopgap. The receiving card ACKs a brightness
        write without echoing the level, and the HD-Y1 multifunction card reports
        only its own auto-brightness output - polling it while the wall was set
        manually to 30% returned the auto minimum (23) every time, with 30
        appearing nowhere in the block. See PROTOCOL.md "Offset 18 does NOT track
        manual brightness"."""
        if self.last_set_pct is None:
            return (None, None)
        from hd_bright import pct_to_scaled
        return (int(self.last_set_pct), int(pct_to_scaled(self.last_set_pct)))

    def read_sensor(self):
        """(light, valid). Two different Huidu sensor architectures:

        * **With an HD-Y1 multifunction card** there is no sensor port; the card
          runs the ambient loop in hardware. Returns (None, False) - use
          set_auto(True) instead of a software curve.
        * **Without one**, a standalone sensor streams on its own COM port
          (`sensor_port`). Returns a 0-254 value where higher = brighter.

        The value is **NOT lux**, and it is inverted at the wire level (the raw
        reading rises as light falls) - hd_sensor.light_from_raw handles that.
        Curves authored for NovaStar lux walls do not transfer; see PROTOCOL.md.
        `valid` is False while the sensor is mid-ramp or its reading is stale."""
        if not self.sensor_port:
            return (None, False)
        try:
            if self._sensor is None:
                from hd_sensor import HdSensor
                self._sensor = HdSensor(self.sensor_port)
            return self._sensor.read_light()
        except Exception:
            self._sensor = None
            return (None, False)

    def set_brightness(self, pct):
        """Set a level (and disable hardware auto). Returns the applied percent."""
        if not self.ensure():
            return None
        try:
            from hd_bright import set_brightness as _sb
            applied = _sb(self.ser, pct, self.template, auto=False)
            if applied is None:
                return None
            self.last_set_pct = int(applied)
            return int(applied)
        except Exception:
            self.close()
            return None

    def set_auto_range(self, min_pct=None, max_pct=None):
        """Clamp the HD-Y1's own ambient loop to a brightness range.

        This is how an HD-Y1 wall's ambient brightness is steered: with auto
        enabled the card runs the loop itself and IGNORES the manual level bytes,
        so min/max is the only lever. Enable the loop with set_auto(True).

        Unlike the brightness template this block is GENERIC - one captured on
        any wall sets the range on any other (verified on two walls), so
        `auto_template` is optional and falls back to the bundled default.
        Returns (min, max) applied, or None."""
        if not self.ensure():
            return None
        try:
            from hd_bright import (load_auto_template, set_auto_range as _sar,
                                   DEFAULT_AUTO_TEMPLATE)
            src = self.auto_template or DEFAULT_AUTO_TEMPLATE
            tpl = (src if isinstance(src, (bytes, bytearray))
                   else load_auto_template(src))
            return _sar(self.ser, min_pct, max_pct, tpl)
        except Exception:
            self.close()
            return None

    def read_auto_output(self):
        """(output_pct, light) - the HD-Y1's LIVE on-card brightness and light
        reading, or (None, None). Read-only. Lets the control loop report what the
        card is actually doing in ambient (where it owns the level), so the wall
        shows a real brightness on the dashboard instead of nothing."""
        if not self.ensure():
            return (None, None)
        try:
            from hd_bright import read_auto_output as _rao
            r = _rao(self.ser)
            return r if r else (None, None)
        except Exception:
            self.close()
            return (None, None)

    def set_auto(self, enabled=True):
        """Hand brightness to (or take it from) the card's own ambient loop.
        This is Huidu's answer to ambient mode - there is no software curve."""
        if not self.ensure():
            return False
        try:
            from hd_bright import set_auto as _sa
            ok = bool(_sa(self.ser, enabled, self.template))
            if ok and enabled:
                self.last_set_pct = None      # the card owns the level now
            return ok
        except Exception:
            self.close()
            return False


def setup_wall(port=None, baud=None, template_path=None, verbose=True):
    """One-shot setup for a newly deployed client: work out which vendor this wall
    is and, if it is Huidu, acquire its per-wall brightness template from the
    hardware. Returns a dict describing what happened.

    Huidu brightness is sent by replaying that wall's own 521-byte sending-card
    block, so each wall needs its OWN template - one carries that wall's EDID,
    timings and geometry, and pushing it at a different wall would reconfigure it.
    Setup therefore never copies a template between walls; it either reads one off
    this wall or reports that manual provisioning is needed.
    """
    def say(m):
        if verbose:
            print(m)

    nova = NovaLink(port=port, baud=baud)
    if nova.connect():
        say(f"  · vendor: NovaStar on {nova.port} @ {nova.baud} - no template needed")
        nova.close()
        return {"vendor": "novastar", "ready": True, "template": None}

    hd = HdLink(port=port, baud=baud, template=template_path)
    connected = hd.connect()
    if not connected:
        # connect() also fails when the template is missing, so distinguish the
        # two: probe the link without requiring a template first.
        say("  · no NovaStar; checking for Huidu without a template…")
        if not hd.probe_only():
            say("  · no LED controller found (check cable/port; HDset must be closed)")
            return {"vendor": None, "ready": False, "template": None}

    say(f"  · vendor: Huidu on {hd.port} @ {hd.baud}")
    try:
        from hd_bright import acquire_template, DEFAULT_TEMPLATE, PCT_OFFS
        out = template_path or DEFAULT_TEMPLATE
        tpl = acquire_template(hd.ser, out=out)
        if tpl is not None:
            say(f"  · read this wall's template off the hardware -> {out} "
                f"(level {tpl[PCT_OFFS[0]]}%)")
            hd.template = tpl
            return {"vendor": "huidu", "ready": True, "template": out}
        if connected:
            say("  · using the existing template file (hardware read unavailable)")
            return {"vendor": "huidu", "ready": True, "template": out}
        say("  · NO TEMPLATE. Huidu brightness needs this wall's own sending-card")
        say("    block. Capture HDset pressing Send on this wall, then run:")
        say("      hd_bright.py --extract-template <capture>.pcapng")
        say("    (Automatic acquisition needs hd_bright.TEMPLATE_QUERY - run")
        say("     hd_scan.py --all on a wall to discover it once, for all walls.)")
        return {"vendor": "huidu", "ready": False, "template": None}
    finally:
        hd.close()


def detect_link(port=None, baud=None, template=None):
    """Return a connected NovaLink or HdLink, or None. Tries NovaStar first (it
    identifies itself with a cheap register read), then Huidu. Both ride the same
    CP210x bridge, so only the framing distinguishes them - see led_vendor.py."""
    nova = NovaLink(port=port, baud=baud)
    if nova.connect():
        return nova
    hd = HdLink(port=port, baud=baud, template=template)
    if hd.connect():
        return hd
    return None


if __name__ == "__main__":
    import argparse
    import time
    ap = argparse.ArgumentParser(description="NovaStar control-link smoke test (read only unless --set)")
    ap.add_argument("--led-port", default=None)
    ap.add_argument("--baud", type=int, default=None)
    ap.add_argument("--set", type=int, default=None, help="set a brightness percent once")
    ap.add_argument("--ticks", type=int, default=3)
    a = ap.parse_args()
    link = NovaLink(port=a.led_port, baud=a.baud)
    if not link.connect():
        print("no NovaStar card found"); raise SystemExit(1)
    print(f"connected {link.port} @ {link.baud}")
    if a.set is not None:
        print("set ->", link.set_brightness(a.set))
    for _ in range(a.ticks):
        lux, ok = link.read_sensor()
        pct, raw = link.read_brightness()
        print(f"  brightness={pct}% (raw {raw})   sensor={'~%d lux' % lux if lux is not None else '-'} valid={ok}"
              f"   ambient_target={brightness_for_lux(lux)}")
        time.sleep(1)
    link.close()
