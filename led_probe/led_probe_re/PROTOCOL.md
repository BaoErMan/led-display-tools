# Huidu sending-card "Probe" serial protocol

Reverse-engineered from a USB capture (ataradov USB sniffer) of HDset's
**Screen Configuration -> Probe** with 2 receiving cards attached.

## Physical link
- Sending card = **CP210x USB-UART bridge** (USB `10c4:ea60`).
- Serial settings captured from HDset's CP210x control transfers:
  - `SET_BAUDRATE` (bRequest `0x1E`) data = `00 c2 01 00` -> **115200 baud**.
  - `SET_LINE_CTL` data bits/parity/stop -> **8N1**.
- The LED protocol is carried on the CP210x **bulk** endpoint. (The control
  endpoint only carries CP210x status polling: `GET_COMM_STATUS` 0x10,
  `GET_MDMSTS` 0x08 — irrelevant to the LED protocol.)

## Frame format (both directions) — Ethernet-style
```
55 55 55 55 55 55 55 D5  |  payload (N bytes)  |  CRC32(payload), little-endian (4 B)
\_____ preamble + SFD ____/                       \_ standard zlib/Ethernet CRC32 _/
```
CRC verified on every captured frame (`zlib.crc32`, appended LE).

## Payload header
The payload is a **9-byte header followed by a length-prefixed data area**:

```
payload[0]     command class      (0x01 probe/ACK, 0x03 config readback)
payload[1]     sub-command
payload[2]     receiving-card index
payload[3..6]  (opcode/status — 0x01 in requests, 0x04 in ACK replies at [4])
payload[7:9]   data length, uint16 BIG-endian
payload[9:]    data
```

So a well-formed frame satisfies `9 + data_length == len(payload)`. Verified on
every known frame: the 25-byte probe frames declare `00 10` = 16 (9+16=25) and
the 521-byte config frame declares `02 00` = 512 (9+512=521). `hd_bright_analyze.py
--dump` prints this as its `datalen`/`ok` columns — a cheap structural check that
a frame from an unknown class is real rather than a chance CRC match, and the
basis for constructing well-formed requests for classes not yet observed.

Note this means the width/height field below sits at **data offset 28**
(payload offset 37 minus the 9-byte header).

## Which HDset screen sends what
The command layout mirrors HDset's own UI, which is why the auto-brightness *flag*
and the auto-brightness *levels* end up in different frames:

| HDset section | control | command |
|---|---|---|
| **Sending card parameters** | manual brightness **and** auto-brightness on/off | class `0x02` sub `0x00` target `0x00` (level at 58–65, auto flag at 22) |
| **Multifunction card parameters** | auto-brightness min/max levels | class `0x02` sub `0x01` target `0x78` (min/max at 457/458) |

Only the multifunction-card section polls the HD-Y1 (`01 01 00 78 …`), so captures
taken on the sending-card screen contain **no sensor/monitoring readback at all**.
Plan captures accordingly.

## Probe request — 4 frames host -> card
Payload is 25 bytes. `byte0` = command class, `byte1` = sub-command,
`byte2` = receiving-card index.

| payload (hex)                                              | meaning            |
|-----------------------------------------------------------|--------------------|
| `01 01 00 00 01 00 00 00 10` + `00`×16                    | scan index 0       |
| `01 01 01 00 01 00 00 00 10` + `00`×16                    | scan index 1       |
| `01 01 02 00 01 00 00 00 10` + `00`×16                    | scan index 2       |
| `01 02 00 00 01 00 00 00 10` + `00`×16                    | class 1 / sub 2, idx 0 |

## Probe response — frames card -> host (same framing)
A **present** receiving card answers an index scan with two frames:

1. **ACK frame** — 25-byte payload, `payload[0]=0x01`:
   `01 01 <idx> 00 04 00 00 00 10 AA99 0000 1006 0100 00 AA×7`
   (`1006` looks like a card-type/model code; `AA99`/`AA…` are markers.)

2. **CONFIG frame** — 521-byte payload, `payload[0]=0x03`: full readback of the
   receiving card. Decoded field:
   - **Width / Height**: two uint16 **big-endian** at payload **offset 37**.

An **absent** index returns only the ACK frame (no CONFIG) — that's how Probe
counts the connected cards.

### Captured result (2 cards)
| index | width × height |
|-------|----------------|
| 0     | 96 × 96 (`00 60 00 60`) |
| 1     | 80 × 80 (`00 50 00 50`) |
| 2     | none (ACK only) |

## Brightness — class `0x02` (DECODED)

Reverse-engineered from `set_100/80/60/20.pcapng` + `set_autobrightness.pcapng`
(HDset brightness screen, **pressing Send** each time).

Pressing Send emits **exactly one** host->card frame — a full 512-byte screen-config
block, not a small targeted command:

```
class 0x02, sub 0x00, idx 0x00, payload 521 B  (9-byte header + 512 data)
```

The card answers with a 25-byte class `0x01` ACK
(`01 00 00 00 04 00 00 00 10 aa99 0000 1006 0100 00 aa×7`) — the same ACK shape the
probe uses. **It does not echo the brightness**, so there is no readback path here.

### Fields decoded

| payload offset | data offset | meaning |
|---|---|---|
| 22 | 13 | **auto-brightness enable**: `0x00` = manual, `0x01` = auto (hardware) |
| 58, 60, 62, 64 | 49, 51, 53, 55 | brightness as a **direct 0–100 percent** (`0x64` = 100 %) |
| 59, 61, 63, 65 | 50, 52, 54, 56 | same level on a **0–128 scale** = `pct * 128 // 100` (**floor**, not round) |

Bytes 57–65 form the run `ff` + four identical `(percent, scaled)` pairs — four
channels, all driven together by HDset's master slider:

```
  20%:  ff 14 19 14 19 14 19 14 19
  60%:  ff 3c 4c 3c 4c 3c 4c 3c 4c
  80%:  ff 50 66 50 66 50 66 50 66
 100%:  ff 64 80 64 80 64 80 64 80
```

Floor confirmed: `20*128//100 = 25` (round would give 26) and `60*128//100 = 76`
(round would give 77) — both match the capture.

Across the four levels **only those 8 bytes change**; everything else in the block
is identical. Switching to auto-brightness changes **exactly one byte** — offset 22,
`0x00 -> 0x01` — with the level bytes left at their previous value.

### The level bytes do not govern while auto is on (hardware-observed)
A frame carrying `auto = 1` **and** a level of 100 % was sent to a wall sitting at
40 %; the wall then tracked the light sensor normally (dimming when it was covered)
rather than staying at 100 %. So once offset 22 is set, the HD-Y1's ambient loop
owns the level and offsets 58–65 do not stick. Setting both in one frame is still
the tidier thing to do — it is what HDset does — but the level is only what the
wall falls back to once auto is turned off again.

### Answering the HD-Y1 hardware-auto question
Auto-brightness **is** a hardware flag inside this block, so the multifunction card
runs the ambient loop itself. To take dashboard control, write offset 22 = `0x00`
in the same frame that sets the level — no separate auto-disable command is needed.

### Setting brightness in practice
Because the command is the whole config block (EDID, timings, geometry and all),
the safe method is **patch-and-replay**: take a class-0x02 frame captured from
*that specific wall*, overwrite offsets 22 and 58–65, recompute the CRC32, send.

> **Do not replay a template captured from a different wall** — it would push that
> wall's entire screen configuration onto this one. `hd_bright.py` therefore
> requires an explicit per-wall template.

## Auto-brightness settings + the multifunction card — class `0x02` sub `0x01`

From `change_auto.pcapng` (HDset auto-brightness screen on the **HD-Y1
multifunction card**; min 71 % -> 23 %, max 97 % -> 56 %).

### `payload[3]` is a target selector
Comparing the four command headers we now have makes it explicit:

```
receiving-card probe : 01 01 00 00 01 00 00 00 10     payload[3] = 0x00
multifunction poll   : 01 01 00 78 01 00 00 00 10     payload[3] = 0x78
brightness write     : 02 00 00 00 00 00 00 02 00     payload[3] = 0x00
auto-settings write  : 02 01 00 78 02 00 00 02 00     payload[3] = 0x78
```

**`payload[3]`: `0x00` = receiving card, `0x78` = multifunction card (HD-Y1).**
So the class/sub/target triple is what selects a command, and brightness
(`0x02`/`0x00`/`0x00`) and auto-settings (`0x02`/`0x01`/`0x78`) are siblings.

### Polling the multifunction card
`01 01 00 78 01 00 00 00 10` + `00`×16 makes the HD-Y1 answer with a 521-byte
class `0x03` block. HDset polls this ~once a second on the auto-brightness screen.
Decoded fields (payload offsets):

| offset | reading | evidence |
|---|---|---|
| **15** | **ambient light sensor**, raw 0–255 | covered -> `3`, bright -> `211` in `block and unblock sensor.pcapng` |
| **18** | **live auto-brightness OUTPUT percent**, clamped to `[min,max]` | swings 23→47→31→**100**→38 while the *settings never changed*, following offset 15 |
| 19 | output on the 0–128 scale, `round(pct*1.28)` | 31→40, 38→49 (floor would give 39, 48) |
| **469** | **configured MIN percent** | `71` -> `23` when min was changed; untouched by light |
| **470** | **configured MAX percent** | `56` -> `100` when max alone was changed; untouched by light |
| 14 | non-zero only during rapid light changes (`0,0,0,2,2,4,0,2,0`) | a transition/settling flag? undecoded |
| 50–53 | vary every poll with no relation to covering the sensor | undecoded — do **not** assume temp/voltage |
| **268** | **poll counter**, +1 per reply | `205,206,…,220` |

> **Correction.** Offset 18 was initially read as the MIN setting, because in
> `change_auto.pcapng` it moved 71 -> 23 exactly when min did. The sensor capture
> disproves that: with the settings held constant it ranges over the whole
> `[23,100]` band. It had merely been *sitting at* min, which is where the output
> parks in dim light. MIN/MAX live at 469/470.

### Offset 18 does NOT track manual brightness — settled, negative
`manual_then_multifunction.pcapng` sets **30 %** manually on the sending-card
screen, then switches to the multifunction section and polls 17 times. Offset 18
reads **23** in every single one (the auto MIN, where the output parks with auto
off), and the value `30` appears **nowhere in any readback**. HDset's own UI shows
23 % on that screen too.

**Conclusion: the HD-Y1 reports only its own auto-brightness output, not the wall's
manual level. There is no manual-brightness readback on this link**, so
`HdLink.read_brightness()` reporting the last value we set is the permanent design,
not a stopgap.

The card applies a settings write **asynchronously** — the first poll after the
write still returned the old values; the next one showed the new ones.

### MIN / MAX
| frame | offsets | value |
|---|---|---|
| class-0x02 **write** | **457, 458** | `(23, 56)`, then `(23, 100)` — **confirmed twice** |
| readback, `change_auto` before | 457, 458 | `(71, 97)` |
| readback, `change_auto` after / `set_max_only` / sensor capture | 469, 470 | `(23, 56)` -> `(23, 100)` |

**In the write the pair is at 457/458**, confirmed in three separate captures —
that is the offset to use when constructing an auto-settings command.

**In the readback there are two layout variants**, 12 bytes apart, and which one
you get depends on the command that preceded the poll. `manual_then_multifunction.pcapng`
switches between them twice inside a single capture:

| preceding command | pair at |
|---|---|
| brightness write (`0x02`/`0x00`/`0x00`) | **469, 470** |
| query `0x01`/**`0x02`**/`0x78` | **457, 458** |
| auto-settings write (`0x02`/`0x01`/`0x78`) | **469, 470** |

So the earlier "12-byte shift" was not memory corruption — it is a second, stable
layout. A parser must **accept both**: read the pair from 469/470, and fall back to
457/458 (or locate it by value). Do not hard-code one offset.

The rest of that tail region is still full of pointer-shaped words
(`.. 9e 58 00`, `f0 ca 58 00`), so treat anything else there as unreliable.

### A second multifunction query: `0x01` / `0x02` / `0x78`
`01 02 00 78 01 00 00 00 10` + `00`×16 — same shape as the sub-`0x01` poll and
answered the same way. Its effect on the readback layout is noted above; its
purpose is otherwise undecoded.

## There is NO read path for the sending-card block (settled, negative)
The brightness template is the class-0x02 *sending card parameters* block. It
cannot be read from the hardware:

- **`sending_card_read.pcapng`** — HDset's *Sending Card Parameters* screen was
  opened with the sniffer running. **Zero bulk writes.** The screen sends nothing
  at all, so HDset populates it from its own local project data rather than
  querying the wall.
- **A 256-query sweep** of `class 0x01, sub 1, target 0-255` answered on every
  target but never returned a block with the brightness signature — the target
  byte is not an address filter for that query.
- The two class-0x03 readbacks we do have (receiving card, multifunction card)
  carry neither the EDID nor the brightness bytes.

**Consequence:** a fleet client cannot acquire its template from the wall. The
block must come from a capture of HDset pressing Send, or from a per-model
template verified to be wall-invariant. `hd_bright.TEMPLATE_QUERY` stays `None`.

### A detect/hello query: `01 00 ff 10 03 …`
`0100ff1003000000 10` + `00`×16 — class `0x01`, sub `0x00`, idx `0xff`,
target `0x10`, and byte 4 = `0x03` (every other query uses `0x01`). Sent once
before a probe; answered with the ordinary 25-byte ACK. Looks like a
"who's there" / session hello.

### Not yet decoded
- **Reading** the current brightness. HDset never reads it back in these captures.
  The class `0x03` config readback (from Probe) is also 512 data bytes but does
  **not** share this layout — its `0xff` marker sits at offset 54 rather than 57 —
  so the offsets above cannot be assumed to transfer. Needs a dedicated capture of
  an HDset read/refresh at a known level, or live probing.
- The light-sensor **units**. Offset 15 is confirmed to be the sensor (covered `3`,
  bright `211`) but it is a raw 0–255 count with **no mapping to lux** — unlike the
  NovaStar sensor, which reports lux directly. Treat it as a relative reading.
- The auto-brightness **curve** between min and max (only the endpoints are known).
- The purpose of query `0x01`/`0x02`/`0x78`.
- The auto-brightness **curve** between min and max (only the endpoints are known).

## The standalone light sensor (no multifunction card)
A third sensor type, used on Huidu systems without an HD-Y1. It hangs off its own
USB-serial COM port and does **not** speak the LED protocol at all — no preamble,
no CRC32. It streams continuously at **9600 baud**; nothing needs to poll it.

Read live with `sensor_listen.py --port <COM> --baud 9600 --watch`.

### Record format (CR/LF delimited ASCII, 15 bytes + `\r\n`)
```
C9 "S01" "P7D" "V0E2" "v0E2" \r\n
```
| field | width | observed | meaning |
|---|---|---|---|
| `0xC9` | 1 B | constant | start-of-record marker |
| `S` | 2 hex | `01` | sensor id / address |
| **`P`** | **2 hex** | 73 uncovered → 165+ covered | **the reading — 8-bit, the only field that moves** |
| `V` | 3 hex | `0E2` = 226, constant | undecoded (supply voltage?) |
| `v` | 3 hex | `0E2` = 226, constant | undecoded |

Parse generically as "a letter followed by hex digits" — `sensor_listen.py`'s
`parse_fields()` does exactly that, so the format is read rather than hard-coded.
Note `V` and `v` are **different fields**; case matters.

### `P` is INVERTED — it measures darkness. Calibrated.
Two full cover/uncover cycles, each held to a settled plateau:

| condition | settled `P` |
|---|---|
| torch directly on the sensor | **1** |
| ordinary indoor ambient | **~17** |
| fully covered | **255** (saturates the 8-bit ceiling) |

So **brightness must be derived from `(255 - P)`, not `P`**. Wiring it the obvious
way round would dim the wall at night and brighten it in daylight.

This is the opposite sense to the NovaStar sensor (lux, rises with light) and to
the HD-Y1's offset 15 (rises with light). Three sensors, and this is the only
inverted one — **do not assume a shared convention**.

### It is slow AND slew-limited
- **One reading per ~10 s.**
- During a large change the value ramps at a **dead-constant ~30 units per
  reading** in both directions (`46,76,106,136,166,196,225,255` going dark;
  `225,196,166,136,106,76,47,17` coming back). That is firmware slew-limiting,
  not a physical response — a full-range swing takes **~80 s** to be reported.

**A mid-ramp sample is not a light measurement**, it is a point on the ramp toward
one. `hd_sensor.HdSensor.read_light()` reports `valid=False` while ramping and
when the reading is stale, so a control loop cannot act on one. Any loop must be
slower than the sensor, and short cover/uncover tests alias badly and prove
nothing.

### Reading it
`hd_sensor.py` implements all of the above — parsing, inversion, and the
ramp/staleness gate:

    python hd_sensor.py --port /dev/ttyACM1        # follow the reading
    python hd_sensor.py --port COM7 --once         # one reading, for scripts

In the runtime it is wired to `HdLink(sensor_port=...)`, kept separate from the
LED link because it is a different USB device. `read_light()` returns 0–254 with
**higher = brighter**; it is not lux, so NovaStar curves do not transfer.

> **Analysis trap.** The first live run guessed a *fixed* 8-byte record on this
> CR/LF-delimited stream. Every record was then misaligned, so every byte offset
> appeared to swing wildly and eight offsets were flagged as "the sensor reading".
> All of them were artifacts. Always establish framing before attributing
> variance — `is_line_framed()` is now checked first for this reason.

## Reproducing it
`hd_probe.py` (pyserial) opens `/dev/ttyUSB0` at 115200 8N1, sends the four
`build_frame(payload)` frames, reassembles the reply stream with `deframe()`
(CRC-validated), and reports each card's geometry. See that file for details.

**Pacing matters:** HDset sends one query, waits for that card's reply, then
sends the next (the 4 commands are ~0.5 s apart in the capture). Blasting all
four back-to-back overruns the card and drops replies, so the script reads each
reply before sending the next frame.

Verified on hardware: matches the capture byte-for-byte (1214 bytes, 6 frames,
2 cards = 96x96 + 80x80).

## Running natively on Linux
The sending card is a CP2102 (serial `0001`). It must be released from the
winboat Windows VM (detach it in winboat's USB panel) so the Linux `cp210x`
driver binds it as `/dev/ttyUSB0`. HDset and the script cannot share the port.

## Capture artifacts (in this directory)
- `probe.pcapng` — original Probe capture.
- `baud.pcapng`  — capture showing `SET_BAUDRATE` = 115200.
- `all_data.tsv` — extracted USBLL DATA payloads from `probe.pcapng`.
