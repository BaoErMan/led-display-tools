# Huidu notes — how it behaves, and what to watch for

Reference for the Huidu side of this bundle. The integration is **done** — the
client detects the vendor itself and Huidu support ships here. This file records
the protocol facts that shape how it behaves, so they are not rediscovered the
hard way. Full decode: `client/led_probe/led_probe_re/PROTOCOL.md`.

---

## Four behavioural differences from NovaStar

These are protocol facts, not implementation gaps. Each is settled.

**1. Huidu brightness cannot be read back.** The receiving card ACKs a write
without echoing the level, and the HD-Y1 reports only its own auto output (polling
it while the wall was set manually to 30 % returned the auto minimum every time).
`HdLink.read_brightness()` therefore returns what the client last set, and `None`
until it sets something. Where the dashboard distinguishes "measured" from
"commanded", Huidu walls are the second kind.

**2. Huidu ambient does not use a lux curve.** An HD-Y1 runs the ambient loop on
the card: the client calls `set_auto(True)` and clamps it with
`set_auto_range(min, max)`. A wall with a standalone sensor instead uses a software
map, but its value is **0–254, not lux** — a NovaStar curve does not transfer.
The dashboard shows Huidu walls an **Ambient range** control, not the curve editor.

**3. The BRIGHTNESS template is per-wall and must not be shared.** That command
carries the wall's entire screen configuration (EDID, timings, geometry).
`HdLink.connect()` re-probes the wall at startup and **refuses a template whose
fingerprint does not match**. If no fingerprint was recorded the check passes, so
it cannot break an existing deployment — but always record one.

**4. The AUTO-RANGE block is NOT per-wall.** Opposite of (3), and easy to conflate.
It carries no EDID/timings/geometry; a block captured on one wall was verified to
set the range on a different wall and read back correctly. `default_auto.bin` ships
with the client, so `--hd-auto-template` is only an override.

---

## Commissioning a wall

    python provision_wall.py --port COM8 --name wall_north --config <export>

`<export>` is a screen-config export — **`.sss`** (newer HDset) or **`.ssx`**
(older, e.g. v2.1.3.46, where `net_default.xml` holds only the box config) — or
`net_default_new.xml`, or a folder to auto-scan. All verified.

Writes `walls/wall_north.bin` plus its `.wall.json` fingerprint. Start the client
with `--hd-template walls/wall_north.bin`.

**No USB capture or sniffer is needed** for either template: the brightness block
comes from HDset's own config, and the auto-range block is bundled. `--capture`
remains as a fallback where no config file holds the block (`docs/CAPTURE.md`).

Re-provision if anyone reconfigures the wall in HDset — the fingerprint catches a
wrong *wall*, not a stale config for the right one.

---

## Checking a template belongs to a wall

    # definitive, no hardware: export a fresh config from the wall first
    python led_probe/led_probe_re/hd_template_check.py walls/wall_north.bin --config fresh.sss

    # or against the fingerprint recorded at commissioning
    python led_probe/led_probe_re/hd_template_check.py walls/wall_north.bin --port COM8

`SAME WALL` means the only differences are the brightness level and auto flag —
the two fields that legitimately change between exports.

---

## Verifying before rollout

    # 1. offline: the template patches correctly
    python led_probe/led_probe_re/hd_bright.py --template walls/wall_north.bin --set 40 --dry-run

    # 2. on hardware, with HDset (and its localserver) CLOSED so the port is free
    python led_probe/led_probe_re/hd_probe.py --port COM8            # cards detected?
    python led_probe/led_probe_re/hd_bright.py --port COM8 --template walls/wall_north.bin --set 30
    python led_probe/led_probe_re/hd_bright.py --port COM8 --template walls/wall_north.bin --set 100

Expect a 37-byte ACK and a visible change. **Watch the wall** — an ACK only proves
the card accepted a well-formed frame, not that the value landed where we think.
For the auto range, `hd_auto_readback.py --port COM8 --expect 25,75` checks it
directly rather than trusting the ACK.

---

## Server

The server is **not** vendor-neutral by accident — it needed one change:
`/api/led_control` hard-coded `led_vendor='novastar'` and now takes the vendor from
the client payload (defaulting to novastar, so older clients still report
correctly). The dashboard also branches by vendor: Ambient range for Huidu, curve
editor for NovaStar. No schema migration — `led_vendor` was already `VARCHAR(16)`.
