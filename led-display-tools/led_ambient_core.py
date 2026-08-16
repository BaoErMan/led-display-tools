#!/usr/bin/env python3
"""led_ambient_core.py - vendor-agnostic ambient-brightness engine.

Reads the STANDALONE light sensor (the 8-bit unit on its own COM port; see
hd_sensor.py, 0-254 where higher = brighter) and drives an LED controller's
brightness from it, mapped between a min and a max percent. The controller may be
**NovaStar or Huidu** - both expose set_brightness(pct) through led_control, so the
same sensor loop drives either.

This is the shared engine behind:
    led_ambient.py       - command-line runner
    led_ambient_gui.py   - Tkinter GUI (Windows + Linux)

Design: no I/O in __init__; connect() opens the ports and reports what it found;
step() does one read->map->maybe-write cycle and returns a status dict the caller
renders however it likes. Soft-fails throughout - a dropped port or a mid-ramp
sensor sample never raises at the caller.
"""
import os
import sys
import time
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_LED_PROBE = os.path.join(_HERE, "led_probe")
for _p in (_LED_PROBE,
           os.path.join(_LED_PROBE, "nova_probe_re"),
           os.path.join(_LED_PROBE, "led_probe_re")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)


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


class AmbientController:
    """One standalone sensor -> one LED controller (NovaStar or Huidu).

    vendor: 'auto' (detect NovaStar then Huidu on led_port), 'novastar', or 'huidu'.
    template: required for Huidu (this wall's brightness template); ignored otherwise.
    """

    def __init__(self, sensor_port, led_port=None, baud=None, vendor="auto",
                 template=None, min_pct=15, max_pct=90, light_lo=0, light_hi=254,
                 deadband=2, fail_pct=None, fail_after=120.0, dry_run=False,
                 demo=False):
        self.sensor_port = sensor_port
        self.led_port = led_port
        self.baud = baud
        self.vendor = vendor
        self.template = template
        # tunables - safe to change live from the GUI between steps
        self.min_pct = float(min_pct)
        self.max_pct = float(max_pct)
        self.light_lo = int(light_lo)
        self.light_hi = int(light_hi)
        self.deadband = int(deadband)
        self.fail_pct = None if fail_pct is None else float(fail_pct)
        self.fail_after = float(fail_after)
        self.dry_run = bool(dry_run)
        # Demo mode simulates a sensor and needs no hardware / no pyserial - so the
        # GUI can be tested anywhere. It never opens a port or writes to a wall.
        self.demo = bool(demo)
        self._t0 = time.time()

        self.link = None            # NovaLink | HdLink
        self.found_vendor = None
        self.sensor = None
        self.last_set = None
        self._last_valid_t = time.time()
        self._failed_applied = False

    # -- lifecycle ---------------------------------------------------------- #
    def connect(self):
        """Open the LED link and the sensor. Returns (ok, message)."""
        if self.demo:
            self.found_vendor = "demo"
            self._t0 = time.time()
            return (True, "DEMO mode - simulated sensor, no hardware, no writes")
        from led_control import NovaLink, HdLink, detect_link
        v = (self.vendor or "auto").lower()
        try:
            if v == "novastar":
                link = NovaLink(port=self.led_port, baud=self.baud)
                self.link = link if link.connect() else None
                self.found_vendor = "novastar" if self.link else None
            elif v == "huidu":
                if not self.template:
                    return (False, "Huidu needs this wall's --template")
                link = HdLink(port=self.led_port, baud=self.baud, template=self.template)
                self.link = link if link.connect() else None
                self.found_vendor = "huidu" if self.link else None
            else:   # auto
                self.link = detect_link(port=self.led_port, baud=self.baud,
                                        template=self.template)
                self.found_vendor = (
                    "novastar" if type(self.link).__name__ == "NovaLink"
                    else "huidu" if type(self.link).__name__ == "HdLink"
                    else None)
        except Exception as e:
            return (False, f"LED controller error: {e}")

        if self.link is None:
            hint = ("no LED controller answered. Check the cable/port and that "
                    "NovaLCT/HDset is closed")
            if v == "huidu":
                hint += " (a template recorded for a different wall is refused)"
            return (False, hint)

        # open the standalone sensor (independent of the controller vendor)
        try:
            from hd_sensor import HdSensor
            self.sensor = HdSensor(self.sensor_port)
            if not self.sensor.open():
                return (False, f"cannot open sensor port {self.sensor_port} "
                               f"(held by another program?)")
        except Exception as e:
            return (False, f"sensor error: {e}")

        return (True, f"{self.found_vendor} on {self.link.port} @ {self.link.baud}"
                      f"; sensor on {self.sensor_port}")

    def close(self):
        if self.sensor is not None:
            try:
                self.sensor.close()
            except Exception:
                pass
            self.sensor = None
        if self.link is not None:
            try:
                self.link.close()
            except Exception:
                pass
            self.link = None

    # -- one cycle ---------------------------------------------------------- #
    def target_for(self, light):
        return brightness_for_light(light, self.min_pct, self.max_pct,
                                    self.light_lo, self.light_hi)

    def _apply(self, pct):
        """Write a level unless dry-run. Returns the applied percent or None."""
        if self.dry_run:
            return int(round(pct))
        try:
            return self.link.set_brightness(pct)
        except Exception:
            return None

    def step(self):
        """One read -> map -> maybe-write cycle. Returns a status dict:
        {t, light, valid, target, applied, held, note}."""
        st = {"t": datetime.now().strftime("%H:%M:%S"), "light": None,
              "valid": False, "target": None, "applied": None, "held": True,
              "note": ""}

        if self.demo:
            # a slow triangle sweep across the full 0-254 range (~120s period) so
            # the sensor bar and the mapped brightness visibly track each other.
            import math
            phase = (time.time() - self._t0) / 120.0
            light = int(127 - 127 * math.cos(2 * math.pi * phase))
            target = self.target_for(light)
            st.update(light=light, valid=True, target=target,
                      applied=target, held=False, note="demo")
            self.last_set = target
            return st

        if self.sensor is None or self.link is None:
            st["note"] = "not connected"
            return st

        light, valid = self.sensor.read_light()
        st["light"], st["valid"] = light, bool(valid)

        if valid and light is not None:
            self._last_valid_t = time.time()
            self._failed_applied = False
            target = self.target_for(light)
            st["target"] = target
            change = self.last_set is None or abs(target - self.last_set) >= self.deadband
            if change:
                applied = self._apply(target)
                if applied is None:
                    st["note"] = "no ACK from controller - will retry"
                else:
                    self.last_set = applied
                    st["applied"], st["held"] = applied, False
            else:
                st["note"] = "within deadband, holding"
        else:
            stale_for = time.time() - self._last_valid_t
            st["note"] = f"sensor not ready (mid-ramp/stale {stale_for:.0f}s)"
            if (self.fail_pct is not None and stale_for >= self.fail_after
                    and not self._failed_applied):
                fp = int(self.fail_pct)
                applied = self._apply(fp)
                if applied is not None:
                    self.last_set, self._failed_applied = applied, True
                    st["applied"], st["held"] = applied, False
                    st["note"] = f"sensor failed -> {fp}%"
        return st
