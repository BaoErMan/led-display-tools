#!/usr/bin/env python3
"""led_ambient_gui.py - a small GUI for the standalone-sensor ambient loop.

Same engine as led_ambient.py (led_ambient_core.AmbientController): read the
standalone light sensor, map it between min/max, write brightness to a NovaStar or
Huidu wall. Built on Tkinter, which ships with Python on Windows and on Linux
(install with `sudo apt install python3-tk` if missing), so it runs on both with
no extra packages.

    python led_ambient_gui.py

Pick the ports (the sensor/LED dropdowns are auto-populated but you can type a name
the list missed), set the brightness map by dragging OR typing each value, press
Start. The loop runs in a background thread; the sensor bar, target and applied
brightness update live, and map changes take effect on the next tick. Save the map
to a file with "Save map…" and re-load it on another display. Tick "Demo (no
hardware)" to watch the mapping with a simulated sensor and no wall.
"""
import json
import os
import queue
import sys
import threading

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception:                       # pragma: no cover - headless / no Tk
    sys.exit("Tkinter is not available. On Linux: sudo apt install python3-tk")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from led_ambient_core import AmbientController   # noqa: E402

# key, label, min, max, default - drives the map widgets AND import/export
MAP_SPEC = [
    ("min_pct",  "min %",      0, 100, 15),
    ("max_pct",  "max %",      0, 100, 90),
    ("light_lo", "light lo",   0, 254, 0),
    ("light_hi", "light hi",   0, 254, 254),
    ("deadband", "deadband %", 0,  20, 2),
]


def list_serial_ports():
    """Every serial port on the machine, or [] if pyserial is absent."""
    try:
        from serial.tools import list_ports
        return [p.device for p in list_ports.comports()]
    except Exception:
        return []


class App:
    def __init__(self, root):
        self.root = root
        root.title("LED Ambient Brightness")
        self.ctl = None
        self.worker = None
        self.stop_flag = threading.Event()
        self.q = queue.Queue()
        self.v = {}
        self.map_vars = {}          # key -> (IntVar, Scale, Spinbox)

        pad = dict(padx=6, pady=3)
        frm = ttk.Frame(root, padding=10)
        frm.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)

        # --- ports + connection (editable comboboxes) -------------------- #
        ttk.Label(frm, text="Sensor port").grid(row=0, column=0, sticky="e", **pad)
        self.v["sensor_port"] = tk.StringVar(value="")
        self.sensor_cb = ttk.Combobox(frm, textvariable=self.v["sensor_port"], width=12)
        self.sensor_cb.grid(row=0, column=1, sticky="w", **pad)
        ttk.Button(frm, text="↻ Refresh", width=9,
                   command=self.refresh_ports).grid(row=0, column=1, sticky="e", **pad)

        ttk.Label(frm, text="Vendor").grid(row=1, column=0, sticky="e", **pad)
        self.v["vendor"] = tk.StringVar(value="auto")
        ttk.Combobox(frm, textvariable=self.v["vendor"], width=12, state="readonly",
                     values=("auto", "novastar", "huidu")).grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(frm, text="LED port (blank=auto)").grid(row=2, column=0, sticky="e", **pad)
        self.v["led_port"] = tk.StringVar(value="")
        self.led_cb = ttk.Combobox(frm, textvariable=self.v["led_port"], width=12)
        self.led_cb.grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(frm, text="Huidu template").grid(row=3, column=0, sticky="e", **pad)
        tf = ttk.Frame(frm); tf.grid(row=3, column=1, sticky="w", **pad)
        self.v["template"] = tk.StringVar(value="")
        ttk.Entry(tf, textvariable=self.v["template"], width=22).grid(row=0, column=0)
        ttk.Button(tf, text="…", width=3, command=self._pick_template).grid(row=0, column=1, padx=(4, 0))

        ttk.Label(frm, text="Interval (s)").grid(row=4, column=0, sticky="e", **pad)
        self.v["interval"] = tk.StringVar(value="10")
        ttk.Entry(frm, textvariable=self.v["interval"], width=8).grid(row=4, column=1, sticky="w", **pad)

        self.v["dry"] = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Dry run (don't write)", variable=self.v["dry"]).grid(
            row=5, column=0, sticky="w", **pad)
        self.v["demo"] = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Demo (no hardware)", variable=self.v["demo"]).grid(
            row=5, column=1, sticky="w", **pad)

        # --- brightness map: drag OR type, + save/load ------------------- #
        mfrm = ttk.LabelFrame(frm, text="Brightness map", padding=8)
        mfrm.grid(row=0, column=2, rowspan=6, sticky="nsew", padx=(16, 0), pady=3)
        for r, (key, label, lo, hi, default) in enumerate(MAP_SPEC):
            self._map_param(mfrm, r, label, key, lo, hi, default)
        io = ttk.Frame(mfrm); io.grid(row=len(MAP_SPEC), column=0, columnspan=3, pady=(8, 0))
        ttk.Button(io, text="Save map…", command=self.save_map).grid(row=0, column=0, padx=3)
        ttk.Button(io, text="Load map…", command=self.load_map).grid(row=0, column=1, padx=3)

        # --- live readout ------------------------------------------------ #
        live = ttk.LabelFrame(frm, text="Live", padding=8)
        live.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(10, 4))
        live.columnconfigure(1, weight=1)
        ttk.Label(live, text="Sensor light").grid(row=0, column=0, sticky="e", padx=6)
        self.light_bar = ttk.Progressbar(live, maximum=254, length=260)
        self.light_bar.grid(row=0, column=1, sticky="ew", padx=6, pady=2)
        self.light_lbl = ttk.Label(live, text="--/254", width=10)
        self.light_lbl.grid(row=0, column=2, padx=6)
        ttk.Label(live, text="Brightness").grid(row=1, column=0, sticky="e", padx=6)
        self.bright_bar = ttk.Progressbar(live, maximum=100, length=260)
        self.bright_bar.grid(row=1, column=1, sticky="ew", padx=6, pady=2)
        self.bright_lbl = ttk.Label(live, text="--%", width=10)
        self.bright_lbl.grid(row=1, column=2, padx=6)

        # --- controls + log --------------------------------------------- #
        btns = ttk.Frame(frm); btns.grid(row=7, column=0, columnspan=3, sticky="w", pady=4)
        self.start_btn = ttk.Button(btns, text="Start", command=self.start)
        self.start_btn.grid(row=0, column=0, padx=4)
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=4)
        self.status = ttk.Label(frm, text="idle", foreground="#666")
        self.status.grid(row=8, column=0, columnspan=3, sticky="w", padx=6)
        self.log = tk.Text(frm, height=8, width=74, state="disabled", wrap="none")
        self.log.grid(row=9, column=0, columnspan=3, sticky="nsew", pady=(6, 0))

        self.refresh_ports()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(200, self._drain)

    # -- widget builders -------------------------------------------------- #
    def _map_param(self, parent, r, label, key, lo, hi, default):
        """A drag Scale + a typeable Spinbox that stay in sync and push the value
        to a running controller live."""
        var = tk.IntVar(value=default)
        guard = {"busy": False}
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="e", padx=4, pady=2)
        scale = ttk.Scale(parent, from_=lo, to=hi, orient="horizontal", length=160)
        scale.set(default)
        scale.grid(row=r, column=1, padx=4, pady=2)
        spin = ttk.Spinbox(parent, from_=lo, to=hi, width=5, textvariable=var)
        spin.grid(row=r, column=2, padx=4)

        def apply(v):
            v = max(lo, min(hi, int(v)))
            var.set(v)
            if abs(float(scale.get()) - v) >= 1:
                scale.set(v)
            self._push(key, v)

        def from_scale(_v=None):
            if guard["busy"]:
                return
            guard["busy"] = True
            apply(int(float(scale.get())))
            guard["busy"] = False

        def from_spin(_e=None):
            if guard["busy"]:
                return
            guard["busy"] = True
            try:
                v = int(float(var.get()))
            except Exception:
                v = default
            apply(v)
            guard["busy"] = False

        scale.config(command=from_scale)
        spin.config(command=from_spin)                 # arrow buttons
        spin.bind("<Return>", from_spin)
        spin.bind("<FocusOut>", from_spin)
        self.map_vars[key] = (var, scale, spin)

    # -- helpers ---------------------------------------------------------- #
    def refresh_ports(self):
        ports = list_serial_ports()
        self.sensor_cb["values"] = ports
        self.led_cb["values"] = ports
        self.status.config(
            text=(f"{len(ports)} serial port(s) found" if ports
                  else "no serial ports listed (type the name, or install pyserial)"),
            foreground="#666")

    def _pick_template(self):
        p = filedialog.askopenfilename(title="Select this wall's template",
                                       filetypes=[("Template", "*.bin"), ("All", "*.*")])
        if p:
            self.v["template"].set(p)

    def _push(self, key, v):
        """Apply a map value to a running controller between ticks."""
        if self.ctl is not None:
            setattr(self.ctl, key, float(v) if key in ("min_pct", "max_pct") else int(v))

    def _mapval(self, key):
        var, scale, _spin = self.map_vars[key]
        try:
            return int(float(var.get()))
        except Exception:
            return int(float(scale.get()))

    def _logline(self, text):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    # -- save / load the brightness map ----------------------------------- #
    def save_map(self):
        p = filedialog.asksaveasfilename(
            title="Save brightness map", defaultextension=".json",
            initialfile="brightness_map.json",
            filetypes=[("Brightness map", "*.json"), ("All", "*.*")])
        if not p:
            return
        data = {k: self._mapval(k) for k, *_ in MAP_SPEC}
        data["_kind"] = "led_ambient_map"
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self._logline(f"[saved map] {p}")
        except Exception as e:
            messagebox.showerror("Save map", str(e))

    def load_map(self):
        p = filedialog.askopenfilename(
            title="Load brightness map",
            filetypes=[("Brightness map", "*.json"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("not a map file")
        except Exception as e:
            messagebox.showerror("Load map", str(e))
            return
        applied = []
        for key, _label, lo, hi, _default in MAP_SPEC:
            if key in data:
                try:
                    v = max(lo, min(hi, int(data[key])))
                except (TypeError, ValueError):
                    continue
                var, scale, _spin = self.map_vars[key]
                var.set(v); scale.set(v); self._push(key, v)
                applied.append(f"{key}={v}")
        self._logline("[loaded map] " + (", ".join(applied) if applied
                                         else "no usable values in file"))

    # -- start / stop ----------------------------------------------------- #
    def start(self):
        if self.worker is not None:
            return
        demo = self.v["demo"].get()
        sensor = self.v["sensor_port"].get().strip()
        if not sensor and not demo:
            self.status.config(text="choose or type the sensor port (or tick Demo)",
                               foreground="#c00")
            return
        try:
            interval = max(1.0, float(self.v["interval"].get()))
        except ValueError:
            interval = 10.0
        if demo:
            interval = min(interval, 1.0)
        self.ctl = AmbientController(
            demo=demo,
            sensor_port=sensor or "DEMO",
            led_port=self.v["led_port"].get().strip() or None,
            vendor=self.v["vendor"].get(),
            template=self.v["template"].get().strip() or None,
            min_pct=self._mapval("min_pct"), max_pct=self._mapval("max_pct"),
            light_lo=self._mapval("light_lo"), light_hi=self._mapval("light_hi"),
            deadband=self._mapval("deadband"), dry_run=self.v["dry"].get())
        self.stop_flag.clear()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.config(text="connecting…", foreground="#666")
        self.worker = threading.Thread(target=self._run, args=(interval,), daemon=True)
        self.worker.start()

    def _run(self, interval):
        ok, msg = self.ctl.connect()
        self.q.put(("connect", ok, msg))
        if not ok:
            return
        while not self.stop_flag.is_set():
            st = self.ctl.step()
            self.q.put(("step", st))
            self.stop_flag.wait(interval)
        self.q.put(("stopped", None))

    def stop(self):
        self.stop_flag.set()
        self.stop_btn.config(state="disabled")
        self.status.config(text="stopping…", foreground="#666")

    # -- UI update from the worker queue (main thread) -------------------- #
    def _drain(self):
        # The re-arm at the end lives in `finally`: this used to catch only
        # queue.Empty, so ANY other error (e.g. a formatting slip in _show)
        # escaped before the re-arm and killed the periodic callback for good -
        # the UI froze and Stop hung, because the "stopped" message was never
        # drained and _teardown() never ran.
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "connect":
                    ok, text = msg[1], msg[2]
                    self.status.config(text=("connected: " if ok else "not connected: ") + text,
                                       foreground=("#080" if ok else "#c00"))
                    self._logline(("[connect] " if ok else "[FAILED] ") + text)
                    if not ok:
                        self._teardown()
                elif kind == "step":
                    self._show(msg[1])
                elif kind == "stopped":
                    self._logline("[stopped]")
                    self.status.config(text="stopped", foreground="#666")
                    self._teardown()
        except queue.Empty:
            pass
        except Exception as e:                       # never let the loop die
            try:
                self._logline(f"[ui error] {type(e).__name__}: {e}")
            except Exception:
                pass
        finally:
            self.root.after(200, self._drain)

    def _show(self, st):
        if st["light"] is not None:
            self.light_bar["value"] = st["light"]
            self.light_lbl.config(text=f"{st['light']}/254")
        else:
            self.light_lbl.config(text="--/254")
        if st["target"] is not None:
            self.bright_bar["value"] = st["target"]
            self.bright_lbl.config(text=f"{st['target']}%")
        # `light` and `target` go None independently: a mid-ramp or stale sample
        # still carries a light value but no target, so format them separately.
        line = f"{st['t']}  "
        if st["light"] is None:
            line += "sensor --"
        elif st["target"] is None:
            line += f"light {st['light']:>3}/254 -> --"
        else:
            line += f"light {st['light']:>3}/254 -> {st['target']:>3}%"
        if st["applied"] is not None:
            line += f"  set {st['applied']}%"
        if st["note"]:
            line += f"   ({st['note']})"
        self._logline(line)

    def _reset_buttons(self):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _teardown(self):
        if self.ctl is not None:
            self.ctl.close()
            self.ctl = None
        self.worker = None
        self._reset_buttons()

    def _on_close(self):
        self.stop_flag.set()
        if self.worker is not None:
            self.worker.join(timeout=2.0)
        if self.ctl is not None:
            self.ctl.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
