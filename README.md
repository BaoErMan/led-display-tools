# LED wall tools — NovaStar + Huidu

Every standalone tool for reading, configuring and reverse-engineering NovaStar
and Huidu LED walls, in one place. Nothing here talks to the fleet server — these
drive the wall directly over its USB/serial link, or work offline on captures.

Assembled 2026-08-15 from `fleet-monitor-brightness-v4.0.2/client` (which carried
the newest copy of nearly everything), plus tools that survived only in the older
research bundles: `nova_probe_re/`, `hdy1-autobright-research.zip`,
`led_ambient_gui.zip`. `nova_cards.py` refreshed 2026-08-16 from **v4.0.5**; no
other tool here changed in 4.0.3–4.0.5.


---[:heart: Sponsor this project](https://github.com/sponsors/BaoErMan) -- Please support my project

## Contents

| | |
|---|---|
| [Install](#install) · [Layout](#layout--why-it-matters) · [Read this first](#read-this-first) | setup and ground rules |
| [Where do I start?](#where-do-i-start) | pick a tool by what you're trying to do |
| [Both vendors](#both-vendors-led_probe) | vendor detection, unified probe |
| [NovaStar](#novastar-live-wall--led_probenova_probe_re) | probe, brightness, sensor, card survey |
| [Huidu](#huidu-live-wall--led_probeled_probe_re) | probe, brightness, templates, sensors |
| [Ambient brightness](#ambient-brightness-top-level) | sensor-driven auto-brightness |
| [Whole-wall utilities](#whole-wall-utilities-top-level) | commissioning, full read report |
| [Offline capture analysis](#offline-capture-analysis) | protocol reverse-engineering |
| [Reference docs](#reference-docs) · [Not included](#deliberately-not-included) | protocol notes, what was left out |

---

## Install

    pip install -r requirements.txt      # pyserial — that's the only package

`led_ambient_gui.py` also wants tkinter (bundled with Python on Windows;
`sudo apt install python3-tk` on Debian/Ubuntu). The offline capture analysers
want `tshark` on PATH. Nothing else.

Ports: `COM*` on Windows, `/dev/ttyUSB*` or `/dev/ttyACM*` on Linux. Almost every
tool takes `--port` (a few use `--led-port`) and most auto-detect the CP210x
bridge and the baud rate if you omit it.

## Layout — why it matters

    led-display-tools/
    ├── led_probe/                  shared runtime layer
    │   ├── led_vendor.py           vendor fingerprint (used by both probes)
    │   ├── led_probe.py            dual-vendor probe
    │   ├── led_brightness.py       NovaStar brightness read
    │   ├── led_control.py          persistent NovaStar link
    │   ├── nova_probe_re/          NovaStar tools + protocol notes
    │   └── led_probe_re/           Huidu tools + protocol notes
    ├── led_ambient*.py, hd_ambient.py, run_gui.*     ambient loop
    ├── led_report.py, provision_wall.py              whole-wall utilities
    ├── walls/                      per-wall Huidu templates (+ fingerprints)
    ├── captures/                   raw USB captures for the analysers
    ├── HUIDU_NOTES.md              Huidu field notes
    └── requirements.txt

**Do not rearrange these directories.** Tools locate each other by relative path
(`sys.path.insert` on their own dir and their parent) — `nova_bright.py` imports
`nova_probe`, `hd_bright.py` imports `hd_probe`, both probes import `led_vendor`
from the parent. Grouping the files by vendor into flat folders would break every
one of them. Run tools by path from anywhere; the imports resolve themselves.

## Read this first

**The vendor software holds the serial port.** HDset (and its `localserver`
helper), NovaLCT and MonitorSite each keep the COM port open. Close them, or every
tool here times out. On Windows, check Task Manager for a lingering
`localserver.exe`.

**Huidu brightness templates are per-wall and dangerous to mix up.** A Huidu
brightness command is not a small "set brightness" message — it is that wall's
entire 521-byte screen-configuration block (EDID, timings, geometry) with the level
patched into it. Sending wall A's template to wall B reconfigures wall B's screen.
Two real walls' blocks differ in 7 geometry bytes outside the brightness field.
Hence `provision_wall.py` always records a fingerprint, `hd_template_check.py`
exists, and `example_wall1.bin` in `walls/` is **reference only — never send it**.

**NovaStar needs no template**; brightness is a plain register write, broadcast to
all cards.

**Reads are safe, writes are not.** `led_report.py`, all `--dry-run` paths, every
`*_probe.py`, `nova_cards.py`, `nova_chain.py` and `hd_scan.py` only read. Huidu
class 0x01 is always a query; class 0x02 carries whole config blocks — never
extend a scanning tool to class 0x02 to "see what happens".

## Where do I start?

| You want to… | Run |
|---|---|
| Find out what kind of wall this even is | `led_probe/led_probe.py --port COM5` |
| Check everything readable on this wall at once | `led_report.py` |
| Commission a new wall for the fleet | `provision_wall.py --port COM8 --config wall.sss` |
| Set brightness — NovaStar | `led_probe/nova_probe_re/nova_bright.py --port COM5 --set 75` |
| Set brightness — Huidu | `led_probe/led_probe_re/hd_bright.py --port COM8 --set 75` |
| Audit NovaStar receiving cards | `led_probe/nova_probe_re/nova_cards.py --port COM5 --ports 4` |
| Run brightness off a light sensor | `led_ambient.py --sensor-port COM7` (or `run_gui.sh`) |
| Work out an unknown protocol field | the [offline analysers](#offline-capture-analysis) |

---

## Both vendors (`led_probe/`)

### `led_probe.py` — one probe, either vendor
Detects the controller family from a frame fingerprint, then dispatches to
`hd_probe` or `nova_probe`. The right first command on an unknown machine.

    python led_probe/led_probe.py --port /dev/ttyUSB0
    python led_probe/led_probe.py --port COM10 --vendor huidu --cards 2
    python led_probe/led_probe.py --port /dev/ttyUSB0 --vendor novastar --ports 2

### `led_vendor.py` — Huidu or NovaStar, from one frame
Both controllers ride the same CP210x bridge, so USB descriptors can't tell them
apart — the framing does. `frame[1]` is the tell: `0x55` → Huidu (mid-preamble),
`0xAA` → NovaStar. `identify()` also validates the trailer checksum. Imported by
both probes; runnable on its own to classify a captured frame.

    python led_probe/led_vendor.py 55aa004a…a156

### `led_brightness.py` — NovaStar brightness read (library-style)
Read-only, NovaStar-only, never raises — returns
`{"serial_port", "vendor", "port", "idx", "raw", "pct"}` or `{"error": …}`. This
is what the fleet client reports to the dashboard, so run it when the dashboard's
number is in doubt: it prints **which card it read**, which `nova_bright.py` does
not. Brightness is global on NovaStar, so one real card gives the wall's value —
`find_card()` takes the first port answering with valid geometry, since the chain
may hang off any output port. Sends no Huidu frames, so it's safe to run blind on
a machine that might be Huidu.

    python led_probe/led_brightness.py --led-port COM5
    # COM5: 60% (raw 153/255, novastar, port1 idx0)

**Valid geometry does not mean "a card."** An MCTRL300 answers every index of an
*unused* port with a well-formed 240x100 block, and two live walls reported 11%
(raw 28) from exactly that filler while their real cards sat at 60%. Since 4.0.7
`find_card()` reads each port's answer at index 177 and takes the first index
whose block **differs** from it, walking 16 indices deep — on those walls the
cards were at port 2 idx 6–9, which a 2-deep scan never reached. A card that
can't be distinguished from the filler is still used as a last resort (an
MCTRL600's clamp *is* its last real card's block) but is flagged `verified:
False`. Nothing anywhere → an error, so the dashboard omits the value rather
than showing a wrong one.

### `led_control.py` — persistent NovaStar link
Opens one CP210x connection, detects baud once, and exposes
`read_brightness` / `read_sensor` / `set_brightness`, reconnecting if an operator
grabs the port in NovaLCT. Every method soft-fails to `None`/`False`. This is the
control-loop backend, not a one-shot tool.

    python led_probe/led_control.py --led-port COM5 --set 60 --ticks 3

---

## NovaStar, live wall (`led_probe/nova_probe_re/`)

Framing: `55 AA` request / `AA 55` reply, checksum `(0x5555 + Σbytes[2:-2]) & 0xFFFF`.
Full notes in `led_probe/nova_probe_re/PROTOCOL.md`.

### `nova_probe.py` — card detection (what NovaLCT's Detect does)
Replays NovaLCT's detection reads: sending-card ID, plus each output port's
receiving-card model and firmware string. Module geometry is *not* part of a
detection pass — use `nova_cards.py` for that.

    python led_probe/nova_probe_re/nova_probe.py --port /dev/ttyUSB0
    python led_probe/nova_probe_re/nova_probe.py --port COM5 --whoami
    python led_probe/nova_probe_re/nova_probe.py --port COM5 --ports 4 --raw

### `nova_bright.py` — read and set brightness
Register `00 01 00 00 02` on dev 0x01, one byte where `0xFF` = 100%. Writes go out
as a **broadcast** (port 0xFF, idx 0xFFFF) exactly as NovaLCT does, re-sending the
default R/G/B gains afterwards unless you pass `--no-gains`. Reads come from a
specific card, since NovaLCT itself never reads the value back.

    python led_probe/nova_probe_re/nova_bright.py --port /dev/ttyUSB0            # read all cards
    python led_probe/nova_probe_re/nova_bright.py --port COM5 --set 75           # 75%, broadcast
    python led_probe/nova_probe_re/nova_bright.py --port COM5 --set-raw 200      # raw 0-255
    python led_probe/nova_probe_re/nova_bright.py --port COM5 --ports 4 --max-idx 255
    python led_probe/nova_probe_re/nova_bright.py --port COM5 --gap 6            # tolerate chain gaps

### `nova_sensor.py` — ambient light sensor
Replays NovaLCT's light-sensor exchange: write `00 3f 00 00 02 = 3c` to trigger,
read 2 bytes from `00 0f 00 00 02`. `--watch` polls so you can cover and uncover
the sensor and confirm which way it moves.

    python led_probe/nova_probe_re/nova_sensor.py --port /dev/ttyUSB0
    python led_probe/nova_probe_re/nova_sensor.py --port COM5 --watch --interval 0.5
    python led_probe/nova_probe_re/nova_sensor.py --port COM5 --no-trigger --watch

### `nova_cards.py` — receiving-card survey, with a misconfiguration check
Walks every port collecting distinct card config blocks, groups them by driver
parameters, and flags two kinds of fault:

- a block that shares a parameter set but **not** a geometry — how a 240×80 panel
  still carrying a 240×100 height was caught on a real wall;
- the **odd one out**: a single card whose parameters match nothing else on the
  wall. It sits alone in its own group, so the first check never compares it —
  a 240×20 block with `params[2 8 0 32]` sat unflagged between 240×100s and
  240×80s while the survey reported "all cards consistent".

A genuine odd-one-out is often deliberate — a real MCTRL600 wall carries a 240x20
strip added to compensate for shipping damage, flagged every survey. `--ack
PORT:IDX` marks a card as deliberate (1-based port, 0-based index — written
the way the warning prints it). It stays in the geometry and is listed as
`acknowledged`, but stops being an issue and drops the "check this in NovaLCT"
advice. Anything new still warns, including a different fault on the same port.
A live wall needs this for a 240×20 strip added to compensate for shipping damage.

Since 4.0.8 it also tells an **empty port** from a populated one. An MCTRL300
answers every index of an unused port with a well-formed 240x100 block, which the
survey used to list as `240x100 idx 0+` and call consistent — describing a port
with nothing plugged in. A block is treated as filler only where the wall proves
it (the value appearing *before* a run that differs from it), so an MCTRL600 —
whose clamp is its last real card's block, and only ever trails — is unaffected.

Honest about counting: an MCTRL600 answers out-of-range indices by repeating the
last card, so an exact count isn't derivable there and `count` comes back `None`
with a `count_note` saying why.

    python led_probe/nova_probe_re/nova_cards.py --port COM5 --ports 4
    python led_probe/nova_probe_re/nova_cards.py --port COM5 --ports 4 --json
    python led_probe/nova_probe_re/nova_cards.py --port COM5 --ack 1:0     # known-deliberate card
    python led_probe/nova_probe_re/nova_cards.py --port COM5 --walk        # every index, with params

Two behaviours worth knowing when reading a `--walk`: the survey discards one
throwaway read first (`--warmup`, default 1) because the first transaction of a
session is unreliable — that 240×20 artifact came from the very first read — and
the walk stops after a run of identical blocks, not identical-and-equal-to-clamp,
which cut a port from 128+ reads to 51 for the same output. Also, the config
blocks carry a volatile field: **digests differ between sessions for the same
card**, so never compare them across runs. Every comparison the survey makes is
within one session.

### `nova_chain.py` — what a port really returns per index
The diagnostic behind that caveat: does the sending card clamp or wrap past the end
of the chain? Read-only, config reads only.

    python led_probe/nova_probe_re/nova_chain.py --port COM5 --ports 2
    python led_probe/nova_probe_re/nova_chain.py --port COM5 --indices 0,1,2,4,16,177,250

**There is no single "out-of-range answer" for a port** — it depends how far past
the end you ask, so probe several distances. On a live MCTRL600 whose port 1 held
nine cards at idx 0-8, indices 9-22 returned its **last** card and index 177
returned its **first**; port 2 of the same controller returned its last card at
both distances. A mismatch between a far probe and a port's trailing run is
hardware behaviour, not a fault — treating it as one is how a real 240x20 card
once got deleted from a survey.

### `nova_model.py` — capture what the controller *is*
Records the sending card's identity together with how that controller answers past
the end of a chain — the two facts that decide how a port must be read. A
diagnostic: `nova_cards.py` deliberately works from block content alone and never
consults it.

    python led_probe/nova_probe_re/nova_model.py --port COM5
    python led_probe/nova_probe_re/nova_model.py --port COM5 --ports 2 --json
    python led_probe/nova_probe_re/nova_model.py --port COM5 --save com5_model.json

### `serial_caps.py` — can this adapter actually do 1048576 baud?
MCTRL600s run at 2²⁰ bps, which isn't a standard termios rate. A Linux driver may
refuse it — or silently substitute a nearby rate, which is the dangerous case:
the port opens, short replies look fine, and every long reply is quietly corrupt.
This asks the driver what it *actually* set and flags disagreement.

    python led_probe/nova_probe_re/serial_caps.py               # list ports
    python led_probe/nova_probe_re/serial_caps.py --port /dev/ttyUSB0

---

## Huidu, live wall (`led_probe/led_probe_re/`)

Framing: `55 55 55 55 55 55 55 D5 | payload | CRC32(payload) LE`; `payload[0]` =
class, `[1]` = sub-command, `[2]` = card index. Class 0x01 queries, class 0x02
writes. Full notes in `led_probe/led_probe_re/PROTOCOL.md`.

### `hd_probe.py` — card detection (HDset's Probe button)
One sub=1 frame per card index, then a sub=2 frame for index 0. A present card
answers ACK + CONFIG (width/height as uint16 BE at payload offset 37); an absent
one answers ACK only — that's how presence is determined.

    python led_probe/led_probe_re/hd_probe.py --port COM10
    python led_probe/led_probe_re/hd_probe.py --port /dev/ttyUSB0 --cards 4
    python led_probe/led_probe_re/hd_probe.py --port COM10 --autodetect     # find the baud
    python led_probe/led_probe_re/hd_probe.py --port COM10 --raw

### `hd_bright.py` — set brightness (patch-and-replay)
Takes this wall's template, patches the level into `payload[58,60,62,64]` (percent)
and `[59,61,63,65]` (pct×128//100), sets the auto flag at `[22]`, recomputes CRC32,
sends. There is **no readback** — the card's ACK doesn't echo brightness. Also
extracts templates from a capture or an HDset config, and writes the HD-Y1
auto-range (min/max at offsets 457/458).

    python led_probe/led_probe_re/hd_bright.py --port COM8 --set 75                  # 75%, manual
    python led_probe/led_probe_re/hd_bright.py --port COM8 --set 40 --dry-run        # show frame only
    python led_probe/led_probe_re/hd_bright.py --port COM8 --auto                    # back to hardware ambient
    python led_probe/led_probe_re/hd_bright.py --port COM8 --auto-min 25 --auto-max 75
    python led_probe/led_probe_re/hd_bright.py --extract-template set_100.pcapng
    python led_probe/led_probe_re/hd_bright.py --from-config wall.sss --template walls/wall_north.bin
    python led_probe/led_probe_re/hd_bright.py --extract-auto-template change_auto.pcapng \
        --auto-template walls/wall_north_auto.bin

Pass `--template walls/<wall>.bin` whenever you're not using the default.

### `hd_template_check.py` — does this template belong to this wall?
The guard against the mix-up described above. Three modes: `--config` diffs the
template against a fresh HDset export (`.sss`, `.ssx` or `net_default_new.xml`) —
the strongest check, since only the level and auto flag may legitimately differ;
`--port` compares the wall's cards against the fingerprint recorded at
commissioning; `--against` diffs two templates.

    python led_probe/led_probe_re/hd_template_check.py walls/wall_north.bin --config fresh.sss
    python led_probe/led_probe_re/hd_template_check.py walls/wall_north.bin --port COM8
    python led_probe/led_probe_re/hd_template_check.py walls/wall_north.bin --against other.bin

### `hd_auto_readback.py` — what auto-range does the HD-Y1 actually hold?
An ACK only proves the frame parsed. This polls the multifunction card (class 0x01 /
sub 0x01 / target 0x78) and reports the configured min/max, reading both known
layouts (457/458 or 469/470 depending on what preceded the poll) and reporting the
plausible one. Also prints the live light reading (offset 15) and live auto output
(offset 18) as context — neither is the setting.

    python led_probe/led_probe_re/hd_auto_readback.py --port COM4
    python led_probe/led_probe_re/hd_auto_readback.py --port COM4 --expect 25,75

### `hd_sensor.py` — the standalone light sensor
For Huidu systems with no multifunction card, where the sensor is its own COM-port
device streaming `C9 "S01" "P7D" "V0E2" "v0E2" \r\n` at 9600 baud. **`P` measures
darkness** — 1 under a torch, ~17 indoors, 255 covered — so brightness is
`255 - P`. It reports once per ~10 s and slews at a fixed ~30 units per reading, so
a full swing takes ~80 s: a mid-ramp sample is not a light measurement, and no
control loop should react faster than that.

    python led_probe/led_probe_re/hd_sensor.py --port /dev/ttyACM1        # follow live
    python led_probe/led_probe_re/hd_sensor.py --port COM7 --once         # one reading, for scripts
    python led_probe/led_probe_re/hd_sensor.py --port COM7 --log day.csv  # leave running a day
    python led_probe/led_probe_re/hd_sensor.py --summarize day.csv        # pick --light-lo/--light-hi

### `sensor_listen.py` — bring up an unknown sensor
When you don't yet know the port, the baud, or the record format. Never writes
unless you pass `--poll`.

    python led_probe/led_probe_re/sensor_listen.py --list
    python led_probe/led_probe_re/sensor_listen.py --port COM5 --scan-bauds
    python led_probe/led_probe_re/sensor_listen.py --port COM5 --baud 9600 --watch

### `hd_scan.py` — hunt for the read command that returns the config block
The open question it was built for: the brightness block has to come from a capture
or an HDset file because no known query returns it. This sweeps (sub, target)
combinations looking for one that does. **Class 0x01 only — it never writes.**

    python led_probe/led_probe_re/hd_scan.py --port COM8                  # curated sweep
    python led_probe/led_probe_re/hd_scan.py --port COM8 --targets 0-255  # exhaustive
    python led_probe/led_probe_re/hd_scan.py --port COM8 --save-template

### `find_config.py` — pull the block out of HDset's own files
The other route to a template with no sniffer: HDset's config screen sends nothing
when opened, so it must populate from local data. Searches files for
wall-independent signatures (EDID magic at payload offset 265, a dense 48-byte run
at 281, the model string at 360), reconstructs a candidate block and validates it
before believing it.

    python find_config.py --scan "C:/Program Files (x86)/HDSet"
    python find_config.py --scan ~/hdset_files --ext .cfg,.dat,.bin
    python find_config.py --scan DIR --extract wall.bin

(run from `led_probe/led_probe_re/`, or give the full path)

---

## Ambient brightness (top level)

### `led_ambient.py` — sensor-driven brightness, either vendor
Reads the standalone 0–254 sensor on its own COM port, maps it between
`--min-pct` and `--max-pct`, and writes to whichever controller is on `--led-port`.
NovaStar needs no template; Huidu needs this wall's.

    # NovaStar, sensor on COM7, controller auto-detected
    python led_ambient.py --sensor-port COM7 --min-pct 15 --max-pct 90

    # Huidu — watch it react before letting it write
    python led_ambient.py --sensor-port COM7 --vendor huidu \
        --template walls/wall_north.bin --min-pct 15 --max-pct 90 --dry-run

    # with the light window measured for this wall
    python led_ambient.py --sensor-port COM7 --light-lo 30 --light-hi 250 \
        --deadband 2 --interval 10 --fail-pct 30 --fail-after 120

**Measure `--light-lo` / `--light-hi` per wall** with `hd_sensor.py --log` /
`--summarize`. The 0/254 defaults are almost never right — a real outdoor wall ran
~30 at night and ~252 in daylight, and the defaults would have stranded it at ~28%
overnight. `--fail-pct` is the brightness to hold if the sensor goes quiet for
`--fail-after` seconds.

### `led_ambient_gui.py` — the same loop with a GUI
Tkinter, so it runs on Windows and Linux with no extra packages. Auto-populated
port dropdowns (you can type one the list missed), drag-or-type brightness map,
live sensor bar, map changes apply on the next tick, save/load the map to a file.
**"Demo (no hardware)" ticks the whole loop against a simulated sensor** — the way
to learn the mapping without a wall.

    ./run_gui.sh          # or: run_gui.bat on Windows
    python led_ambient_gui.py

### `led_ambient_core.py` — the shared engine
`AmbientController`: no I/O in `__init__`; `connect()` opens ports and reports what
it found; `step()` does one read→map→maybe-write cycle and returns a status dict.
Soft-fails throughout. Import this to build your own runner.

### `hd_ambient.py` — **superseded**
The Huidu-only predecessor, kept so existing scripts keep working. Use
`led_ambient.py` for anything new; identical flags plus a required `--template`.

---

## Whole-wall utilities (top level)

### `led_report.py` — read everything, change nothing
Runs every available reading against whatever wall is attached, either vendor, and
prints one summary marking each line `[ OK ]`, `[FAIL]` (applies but didn't read)
or `[ -- ]` (not applicable to this setup). Safe on a live wall: no brightness
write, no config write. One exactness caveat — reading the NovaStar sensor writes
its trigger register first (`003f000002 = 3c`), which is how sampling works and
exactly what NovaLCT does. The Huidu path writes nothing at all.

    python led_report.py                            # auto-detect
    python led_report.py --led-port COM5
    python led_report.py --sensor-port COM7         # include a standalone sensor
    python led_report.py --ports 8 --max-idx 255    # bigger NovaStar rig

### `provision_wall.py` — commission a wall in one step
Detects the vendor, obtains a Huidu brightness template, and records the
fingerprint that stops it being applied to a different wall. NovaStar walls need no
template and are reported ready immediately. Writes
`<outdir>/<name>.bin` and `<name>.bin.wall.json`.

    # Huidu, from HDset's own config — preferred, no capture, no sniffer
    python provision_wall.py --port COM8 --config wall_x.sss --name wall_north

    # Huidu, from a USB capture — only if no config file holds the block
    python provision_wall.py --port COM8 --capture set_100.pcapng --name wall_north

    # NovaStar, or just to see what a wall is
    python provision_wall.py --port COM8

`.sss` (newer HDset), `.ssx` (older) and `net_default_new.xml` all work.

### `walls/` and `led_config.example.json`
`walls/` holds per-wall templates with their fingerprints — see `walls/README.txt`;
`example_wall1*.bin` are development-rig reference files, never to be sent.
`led_config.example.json` is the brightness-config format: a piecewise-linear
lux→percent `curve`, `sensor_fail_pct`, `time_caps` (UTC ceilings that wrap
midnight, applying in manual *and* ambient), and `amb_min`/`amb_max` +
`light_lo`/`light_hi` for the standalone-sensor path.

---

## Offline capture analysis

Reverse-engineering tools. These need `tshark`, not a wall. Both capture formats
are auto-detected: USBPcap/usbmon (software-only, recommended) and the ataradov
usb-sniffer (`usbll`).

**NovaStar**

    # pcap -> all_data.tsv transcript
    python led_probe/nova_probe_re/extract.py captures/novastar/probe.pcap

    # decode the frames in all_data.tsv (already present, so this runs as-is)
    python led_probe/nova_probe_re/analyze.py

    # find the brightness register by diffing captures at known levels
    python led_probe/nova_probe_re/bright_analyze.py set_100.pcap set_50.pcap
    python led_probe/nova_probe_re/bright_analyze.py --dump   cap.pcap
    python led_probe/nova_probe_re/bright_analyze.py --writes cap.pcap
    python led_probe/nova_probe_re/bright_analyze.py --check  cap.pcap

**Huidu**

    # brightness command, from captures named by level (or file:level)
    python led_probe/led_probe_re/hd_bright_analyze.py set_100.pcapng set_50.pcapng
    python led_probe/led_probe_re/hd_bright_analyze.py a.pcapng:100 b.pcapng:50
    python led_probe/led_probe_re/hd_bright_analyze.py --check  cap.pcapng
    python led_probe/led_probe_re/hd_bright_analyze.py --dump   cap.pcapng
    python led_probe/led_probe_re/hd_bright_analyze.py --writes slide.pcapng

    # HD-Y1 auto-range block -> template (tshark only, no pyserial)
    python led_probe/led_probe_re/hd_auto_extract.py wall2.pcapng -o walls/wall2_auto.bin

    # is the auto block generic across walls, or per-wall?
    python led_probe/led_probe_re/hd_auto_compare.py walls/example_wall1_auto.bin wall2_auto.bin

    # standalone sensor with unknown framing
    python led_probe/led_probe_re/sensor_analyze.py --devices sensor.pcapng
    python led_probe/led_probe_re/sensor_analyze.py --track sensor.pcapng --dev 3 --csv out.csv

`hd_autobright_diff.py` is kept for the record only — its question is already
answered (min/max are at 457/458 of the class-0x02/sub-0x01/target-0x78 block, and
HDset doesn't store that block in its config, so only a capture shows it). Its own
docstring says so. Keep it to re-derive the offsets if a firmware moves them.

**`captures/`** holds the small Huidu captures and the log files. The two NovaStar
raw pcaps (44 MB + 77 MB) were left where they are — see
`captures/novastar/WHERE_ARE_THE_PCAPS.txt`. The decoded transcripts
(`all_data.tsv`, `ctrl_out.tsv`) sit next to the analysers that expect them, so
nothing needs re-extracting to get started.

---

## Reference docs

- `led_probe/nova_probe_re/PROTOCOL.md` — NovaStar framing, registers, what a
  detection pass does and does not return
- `led_probe/led_probe_re/PROTOCOL.md` — Huidu framing, class/sub map, block
  offsets, the two auto-range layouts, "not yet decoded" list
- `HUIDU_NOTES.md` — Huidu field notes: HD-Y1 on-card ambient vs standalone sensor,
  template handling, HDset behaviour
- `walls/README.txt` — how templates and fingerprints are stored

## Deliberately not included

Everything server-coupled: the `server/` tree (PHP dashboard, API, SQL schemas,
deploy scripts), `remote_client_comb.py` (the reporting client), `client/deploy/`
(scheduled-task installers) and the fleet `INSTALL.md`. They remain in
`fleet-monitor-brightness-v4.0.2/`.

`requirements.txt` here is **not** the fleet client's — that one pulled in
requests, urllib3, psutil and pyautogui for reporting and screenshots. No tool in
this collection imports any of them.
