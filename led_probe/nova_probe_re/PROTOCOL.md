# NovaStar sending-card serial protocol (NovaLCT "card detection")

Reverse-engineered from an ataradov usb-sniffer capture (`probe.pcap`) of
**NovaLCT** detecting receiving cards, with **3 receiving cards** attached
(1 on output port 1, 2 on output port 2) driving **200 × 100** modules.

This is the NovaStar analogue of the Huidu work in `../led_probe_re/`. The two
protocols are similar in spirit (USB-serial bridge, framed register read/write)
but the framing, addressing and checksum are different.

## Physical link
- Sending card = **CP210x USB-UART bridge** (same vendor control requests as
  Huidu: `GET_COMM_STATUS` 0x10, `GET_MDMSTS` 0x08 status polling on EP0 — noise).
- The LED protocol rides the CP210x **bulk** endpoint (device address 7,
  **endpoint 2**; OUT = host commands, IN = card replies).
- **Baud not captured** (NovaLCT opened the port before the capture started; no
  CP210x `SET_BAUDRATE`). Defaulting to **115200 8N1** (CP210x family default,
  matches Huidu). Confirm on hardware / capture a port-open if a different rate
  is needed.

## Frame format (both directions)
```
 0  1   2    3     4    5    6    7    8 9    10   11 12 13 14 15   16 17   18..        last2
[ST ] [ack][ser][src ][dst][dev][prt][idx ][cmd][  reg / selector ][ len ][ data … ][cksum]
```
| off   | field      | meaning                                                        |
|-------|------------|----------------------------------------------------------------|
| 0:2   | start      | **55 AA** = request (host→card), **AA 55** = reply (card→host)  |
| 2     | ack/flag   | 00 in requests; 00 (occasionally 01) in replies                |
| 3     | serial     | 1-byte sequence counter, **echoed** in the matching reply      |
| 4     | src addr   | **0xFE = PC** (request); becomes the card addr in replies      |
| 5     | dst addr   | 0x00 = sending card; **src/dst are swapped in the reply**      |
| 6     | device     | **0x00 = sending card, 0x01 = receiving card**                 |
| 7     | port       | sending-card output port, 0-based (0 = LCT "port 1")           |
| 8:10  | index      | receiving-card index along that port's chain (uint16 LE)       |
| 10    | command    | **0x00 = read, 0x01 = write**                                  |
| 11:16 | register   | register / selector (see table); read requests carry no payload |
| 16:18 | length     | **uint16 little-endian**: payload bytes (reply) / bytes to read |
| 18:.. | data       | present in replies and in write requests                       |
| last2 | checksum   | see below                                                      |

### Checksum  ✔ verified on 46/46 frames
```
cksum = (0x5555 + sum(frame_bytes[2 : -2])) & 0xFFFF      # stored little-endian
```
i.e. seed `0x5555` plus the unsigned sum of every byte after the 2-byte start
marker up to (not including) the 2 checksum bytes.

### Register / selector values observed
| dev | reg bytes [11:16] | rd len | meaning (observed)                                   |
|-----|-------------------|--------|------------------------------------------------------|
| 01  | `00 00 00 00 02`  | 256    | receiving-card **model/firmware block** (per port, idx=5) |
| 01  | `00 00 00 00 02`  | 1      | per-(port,index) status byte — always returns `0x1c` |
| 00  | `00 02 00 00 00`  | 2      | sending-card status → `00 01`                        |
| 00  | `00 16 00 00 00`  | 8      | sending-card **ID/serial** → `00 30 e2 01 00 00 06 d5` |
| 00  | `00 06 00 00 00`  | 1      | → `ff`                                               |
| 00  | `00 00 00 00 05`  | 256    | sending-card info block, begins ASCII **`NSSD`**     |
| 00  | `00 00 01 00 05`  | 256    | (zeros in this capture)                              |
| 00  | `00 00 00 00 00`  | 256    | config/presence table (`39 f6 01 00 01 01` … card ID … `ff` pad) |

The register field spans 5 bytes [11:16]; the significant byte sits at a
device-specific offset (e.g. `0x16` lands at [12] for the sending card, `0x02`
at [15] for receiving-card reads). Treated as an opaque selector by the tool —
it replays the exact byte patterns NovaLCT used.

## What NovaLCT's detection actually does (one pass)
1. `dev=01 reg=02 idx=5 len=256` on **port 0** and **port 1** → reads the
   receiving-card block. Decoded ASCII includes the firmware string
   **`2023.06.16 MRV416_MCU_V1.8.1.3.B4`** → the cards are **MRV416**.
2. `dev=01 reg=02 len=1` for **(port 0: idx 0,1)** and **(port 1: idx 0,1,2)**,
   each returning the constant `0x1c`.
3. `dev=00` register reads for sending-card status, ID, and the `NSSD`/presence
   blocks (table above).
The whole pass is repeated (NovaLCT polls continuously while the window is open).

## Receiving-card geometry & firmware (from `readback.pcap`)
A second capture of NovaLCT's **"Read Back"** on a populated card supplied the
fields the detection-only `probe.pcap` lacked. Both confirmed **live** by
`nova_probe.py`:

| read (dev=01, idx=0) | reg [11:16]        | returns                                  |
|----------------------|--------------------|------------------------------------------|
| **config block**     | `00 00 00 00 02`   | begins `1c ff ff ff ff ff 3f …`; **geometry = uint16 LE at data offset 23 (width) / 25 (height)** → `78 00 a0 00` = **120 × 160** |
| **firmware block**   | `00 00 00 00 08`   | ASCII e.g. `2024.08.13 MRV416_FPGA_V4.9.0.0.Beta` |

Key corrections to earlier guesses:
- **The geometry read uses receiving-card index `idx = 0`** (first card on the
  chain), at `[8:10]`. The detection pass's `idx = 5` reads a non-existent card
  and returns garbage/zeros — that, not a missing "fetch", is why the block looked
  empty. **No write/trigger is required**; reading `idx=0 reg=0x02` on a live card
  returns the populated block directly.
- The module size **200 × 100** the operator *configured* is the panel pitch, not
  the per-card pixel resolution; the receiving card reports its own canvas
  **120 × 160**, which is what NovaLCT shows and what we read back.

## Brightness  (write command — the first `cmd=0x01` decoded)
Reverse-engineered from ataradov captures of NovaLCT's **Brightness-adjustment**
screen while dragging the slider (`brightness/slide.pcapng`, cross-checked against
`brightness/50.pcapng` and `backto100.pcapng`). Tooling: `brightness/bright_analyze.py`
(`--check` capture health, `--writes` list writes, `--dump`, and a cross-level
correlator); live reader/writer: `nova_bright.py`.

| field        | value                                             |
|--------------|---------------------------------------------------|
| device       | `0x01` (receiving card)                            |
| command      | `0x01` (**write**)                                 |
| register     | `00 01 00 00 02`  (reg bytes [11:16])             |
| length/data  | **1 byte**, a level `0x00..0xff` where `0xff` = 100% |
| addressing   | NovaLCT **broadcasts**: `port=0xFF`, `idx=0xFFFF` (all cards at once) |
| reply        | **0-length** ack (header echoed, no data)         |

Value mapping (verified across levels): `byte = round(pct/100 * 255)` — e.g.
`0x81`=129→50%, `0x98`=152→60%, `0x67`=103→40%, `0x32`=50→20%, `0xff`=255→100%.

A companion write **always follows** each brightness write:
`reg=00 e3 01 00 02`, 4 bytes `f0 f0 f0 00` — the per-channel **R/G/B gains** at
their default `0xf0`; constant regardless of brightness. `nova_bright.py --set`
mirrors NovaLCT by re-sending it (suppress with `--no-gains`).

**Read path — CONFIRMED live.** NovaLCT never *reads* brightness back in any
capture (it tracks the value in its own UI state), but the write register is R/W:
reading `dev=0x01`, specific `port`/`idx`, `reg=00 01 00 00 02`, `len=1` returns the
live level. Verified on hardware — `nova_bright.py --set N` then a plain read
round-trips exactly (set 40→reads 40, 100→100, 2→2).

*Known limitation:* the per-card scan over-reports cards — reads at indices past the
last real card echo the broadcast value rather than returning zeros, so it lists
phantom cards all showing the same level. Since brightness is **global/broadcast**,
a single read (`port 0, idx 0`) is authoritative; the phantom rows are cosmetic.

## Ambient light sensor  (read — verified live)
Reverse-engineered from ataradov captures of NovaLCT's light-sensor / auto-
brightness screen (`brightness/LIGHTDARK.pcapng`, `LIGHTLIGHT.pcapng`) and
confirmed live with `nova_sensor.py --watch` (cover/uncover the sensor). The
screen does a two-step exchange on the **sending card** (`dev=0x00`):

| step | dir | dev | cmd | register        | len | data                       |
|------|-----|-----|-----|-----------------|-----|----------------------------|
| trigger | H>D | 00 | wr `0x01` | `00 3f 00 00 02` | 1 | `3c` (fixed opcode) |
| read    | H>D | 00 | rd `0x00` | `00 0f 00 00 02` | 2 | → 2-byte value (reply)     |

**Value = little-endian uint16**: bit 15 = **sensor present/valid** flag (set when
a sensor is attached); low 15 bits = **light level (~lux)**. Verified live:
covered → `0x0080` (=0), dim room → tens (`0x1d80`=29), phone flashlight →
`0x84d0` (=1232). So `lux = raw_LE & 0x7FFF`, `valid = raw_LE & 0x8000`.

The `003f=3c` write precedes each read in NovaLCT's capture; `nova_sensor.py`
replays it by default, with `--no-trigger` to test reading `000f` standalone.
When auto-brightness is enabled, NovaLCT reacts to a bright reading by issuing the
brightness broadcast write (`0001000002`, see Brightness above) — the full sensor
→ brightness loop was observed in `LIGHTLIGHT.pcapng`.

*Capture note:* the sensor screen polls **slowly**, so short captures catch only a
slice (each `LIGHT*.pcapng` held just a few transactions). Live probing with
`nova_sensor.py` was faster and definitive than correlating captures here.

## Limitations
- **Card count is not cleanly derivable from the 1-byte status reads** (`reg=0x02
  len=1`): they return `0x1c` even one index past the last real card, so `0x1c` is
  a constant echo, not a presence flag. Per-port presence is instead inferred from
  whether the `idx=0` config block reads non-zero (off/absent → zeros).
- **Brightness read register is inferred, not observed** (see Brightness above):
  NovaLCT only writes brightness. Reading the write register back is the working
  assumption until a Brightness-screen-open capture confirms it.

## Hardware verification (live, against the real sending card)
Run on `/dev/ttyUSB0` @ 115200 8N1 after detaching the CP210x from the VM:
- **Link/framing/checksum confirmed:** the sending card answers with checksum-valid
  frames; `nova_probe.py`'s `build_read()` reproduces NovaLCT's request bytes exactly,
  and `parse_reply()` validates the replies.
- **Sending-card ID matches the capture byte-for-byte:** `00 30 e2 01 00 00 06 d5`.
  Its `reg=00` table head `39 f6 01 00 01 01 … 0030e201000006d5 …` also matches.
- **Receiving-card presence, geometry and firmware all read live** via `dev=01
  idx=0` (`reg=0x02` → 120×160, `reg=0x08` → MRV416 firmware string). Panels off →
  zeros (→ "no card"); panels on → populated block. Reports 2 populated ports, e.g.
  `port 1: 120x160 [2024.08.13 MRV416_FPGA_V4.9.0.0.Beta]`. (The earlier idx=5 read
  hit a non-existent card and returned `1c 1d 00…`; using idx=0 fixed it — no
  "fetch" command is needed.)

## Reproducing it
`nova_probe.py` (pyserial) opens the CP210x at 115200 8N1, rebuilds frames with
the NovaStar framing + `0x5555` checksum, replays NovaLCT's detection reads with
its pacing (send one query, read its reply, then the next), validates reply
checksums, and reports the sending-card ID and the receiving-card model/firmware
string. See that file.

**Pacing matters** (as with Huidu): NovaLCT issues one query, waits for the
reply, then sends the next. The card's multi-packet replies arrive as several
short bulk transfers that must be concatenated (see `extract.py`).

## Capture / analysis artifacts (this directory)
- `probe.pcap`    — the usb-sniffer capture of NovaLCT's detection.
- `extract.py`    — pulls bulk frames out of the pcap → `all_data.tsv`
  (drops EP0 CP210x polling; reassembles multi-packet replies; flushes on
  direction change).
- `all_data.tsv`  — `frame# \t dir(H>D/D>H) \t hex` per reassembled bulk burst.
- `analyze.py`    — splits bursts into checksum-validated frames and prints the
  decoded field table; contains the checksum cracker.
