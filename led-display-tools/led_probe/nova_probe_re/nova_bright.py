#!/usr/bin/env python3
"""nova_bright.py - Read (and optionally set) NovaStar LED brightness over the
CP210x serial link, reverse-engineered from ataradov usb-sniffer captures of
NovaLCT's Brightness-adjustment screen. See brightness/ and PROTOCOL.md.

Brightness command (from the captures):
    dev=0x01 (receiving card)  register = 00 01 00 00 02  length = 1 byte
    value is a 0-255 level where 0xff = 100%  (byte = round(pct/100 * 255))
    NovaLCT WRITES it as a BROADCAST: port=0xFF, idx=0xFFFF (all cards at once),
    acknowledged by a 0-length reply. It also re-sends 00 e3 01 00 02 = f0f0f000
    (the per-channel R/G/B gains at their default 0xf0) after each change.

NovaLCT never *reads* brightness back in the captures, so the read path here
reads that same register from a specific card (port,idx). NovaStar MRV registers
are R/W, so this returns the live value; confirm it against a value you set.

Usage:
    python nova_bright.py --port /dev/ttyUSB0                 # read all cards (idx 0-127/port)
    python nova_bright.py --port /dev/ttyUSB0 --ports 4 --max-idx 255   # bigger rig
    python nova_bright.py --port /dev/ttyUSB0 --gap 6         # tolerate longer gaps in a chain
    python nova_bright.py --port /dev/ttyUSB0 --set 75        # set 75% (broadcast)
    python nova_bright.py --port /dev/ttyUSB0 --set-raw 200   # set raw 0-255
    python nova_bright.py --port /dev/ttyUSB0 --raw           # show frames
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

from nova_probe import (Seq, build_read, build_write, transact,   # noqa: E402
                        RX_BLOCK, DEFAULT_BAUD, TX_ID, parse_geometry)

# Same candidates the client and led_report auto-detect over. Kept in sync by
# importing where possible: a tool that assumes 115200 while the rest of the
# bundle auto-detects will silently write at the wrong rate on a 1 Mbps wall.
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from led_brightness import BAUD_CANDIDATES          # noqa: E402
except Exception:
    BAUD_CANDIDATES = (115200, 1048576, 1000000, 921600)

# brightness register (reg bytes [11:16]); dev=0x01 = receiving card, 1 data byte
BRIGHT_REG = bytes([0x00, 0x01, 0x00, 0x00, 0x02])
GAINS_REG = bytes([0x00, 0xe3, 0x01, 0x00, 0x02])   # companion R/G/B gains
GAINS_DEFAULT = bytes([0xf0, 0xf0, 0xf0, 0x00])
BCAST_PORT = 0xFF
BCAST_IDX = 0xFFFF


def pct_to_raw(pct):
    return max(0, min(255, round(pct / 100 * 255)))


def raw_to_pct(raw):
    return round(raw / 255 * 100)


def read_brightness(ser, port, idx, seq, raw=False):
    """Read the 1-byte brightness of one receiving card. Returns int 0-255 or None."""
    reps = transact(ser, build_read(seq.next(), 0x01, port, idx, BRIGHT_REG, 1), raw)
    if reps and reps[0]["data"]:
        return reps[0]["data"][0]
    return None


def card_present(ser, port, idx, seq, raw=False):
    """True if a REAL receiving card answers at (port, idx).

    Presence is decided by VALID GEOMETRY, not merely by non-zero bytes. An empty
    port echoes non-zero data with no geometry (as find_card has always
    documented), so the old any-non-zero test reported every index as populated:
    scans never tripped their miss-gap and walked all 128 indices, counts came
    back as nonsense like "512 cards", and a healthy wall was flagged as an
    echoing port."""
    reps = transact(ser, build_read(seq.next(), 0x01, port, idx, RX_BLOCK, 256), raw)
    data = reps[0]["data"] if reps else b""
    return parse_geometry(data) is not None


def set_brightness(ser, raw_val, seq, with_gains=True, raw=False):
    """Broadcast a brightness level to every receiving card (NovaLCT's method)."""
    raw_val = max(0, min(255, int(raw_val)))
    transact(ser, build_write(seq.next(), 0x01, BCAST_PORT, BCAST_IDX,
                              BRIGHT_REG, bytes([raw_val])), raw)
    if with_gains:      # mirror NovaLCT, which re-sends the default gains
        transact(ser, build_write(seq.next(), 0x01, BCAST_PORT, BCAST_IDX,
                                  GAINS_REG, GAINS_DEFAULT), raw)
    return raw_val


def scan_brightness(ser, ports, max_idx, gap=3, raw=False):
    """Find receiving cards across ports x indices and read each one's brightness.

    Scans idx upward on each port and stops that port only after `gap` CONSECUTIVE
    non-responding indices — a chain can be dozens of cards long, so we don't want
    to cut it short at the first gap, but we also don't want to probe every index
    up to max_idx on empty ports. A single flaky card won't end the scan; a real
    end-of-chain (several misses in a row) will."""
    seq = Seq()
    found = []
    for port in range(ports):
        misses = 0
        for idx in range(max_idx + 1):
            if not card_present(ser, port, idx, seq, raw):
                misses += 1
                if misses >= gap:
                    break                       # end of this chain
                continue
            misses = 0
            val = read_brightness(ser, port, idx, seq, raw)
            found.append({"port": port, "idx": idx, "raw": val})
    return found


def link_answers(ser, seq, strict=True, retries=0):
    """True if this link replies. `strict` decides HOW MUCH has to come back.

    strict=True requires a 256-byte card read to parse. That is the only probe
    that discriminates the exact baud from a near miss: at 4.63% off (1000000 vs
    an MCTRL600's 1048576) short reads still mostly succeed, so probing with the
    8-byte sending-card ID happily "detects" a rate on which every large reply
    will then be corrupt.

    strict=False accepts the sending-card ID too, for a wall whose receiving
    cards do not answer at all - one was seen whose ID read returned nothing
    while its cards were fine, so neither probe alone is sufficient.

    retries=0 throughout: detection must stay fast, and a retry here only
    lengthens the search on rates that are wrong anyway."""
    for port in (0, 1):
        for idx in (0, 1):
            try:
                reps = transact(ser, build_read(seq.next(), 0x01, port, idx,
                                                RX_BLOCK, 256), retries=retries)
                if reps and len(reps[0]["data"]) >= 256:
                    return True
            except Exception:
                pass
    if strict:
        return False
    try:
        return bool(transact(ser, build_read(seq.next(), 0x00, 0, 0, TX_ID, 8),
                             retries=retries))
    except Exception:
        return False


def detect_baud(port, bauds=BAUD_CANDIDATES, settle=0.2, verbose=True):
    """(serial, baud) for the rate this link really runs at, or (None, None).

    ONE pass over the candidates. Per rate it tries a 256-byte card read (the
    only probe that tells the exact rate from a 4.63% near miss) and, if no card
    answers, the 8-byte sending-card ID as a weaker signal. A full reply wins
    immediately; an ID-only hit is remembered and used only if nothing better
    turns up. Probing every rate twice - once strict, once relaxed - doubled the
    wait on a wall that answers slowly, which looked like a hang.

    Each probe can sit on read_reply's timeout, so progress is printed BEFORE
    each rate is tried, not after.
    """
    import time
    fallback = None
    for b in bauds:
        if verbose:
            print(f"  · trying {b} baud…", end="", flush=True)
        try:
            ser = open_serial(port, b)
        except Exception:
            if verbose:
                print(" cannot open", flush=True)
            continue
        # A driver may ACCEPT a rate and quietly set a different one - 1048576 is
        # not a standard Linux termios rate, so this is a real risk there. Probing
        # on a substituted rate wastes a full timeout and can only mislead.
        try:
            actual = ser.baudrate
        except Exception:
            actual = b
        if actual != b:
            try:
                ser.close()
            except Exception:
                pass
            if verbose:
                print(f" driver substituted {actual} - skipping", flush=True)
            continue
        full = weak = False
        try:
            for _pt in (0, 1):
                r = transact(ser, build_read(Seq().next(), 0x01, _pt, 0,
                                             RX_BLOCK, 256), retries=0)
                if r and len(r[0]["data"]) >= 256:
                    full = True
                    break
            if not full:
                weak = bool(transact(ser, build_read(Seq().next(), 0x00, 0, 0,
                                                     TX_ID, 8), retries=0))
        except Exception:
            pass
        try:
            ser.close()
        except Exception:
            pass
        if verbose:
            print(" full reply" if full else ("  partial (ID only)" if weak else " no"),
                  flush=True)
        if full:
            time.sleep(settle)
            try:
                ser = open_serial(port, b)
                ser.reset_input_buffer()
                ser.reset_output_buffer()
            except Exception:
                return None, None
            return ser, b
        if weak:
            # A parseable ID reply means the checksum validated, so this rate is
            # almost certainly right - the card simply has no readable receiving
            # card at ports 0-1 idx 0. STOP here rather than probing the
            # remaining rates: continuing walked an MCTRL300 (115200, the first
            # candidate) all the way through 1048576 - a non-standard rate that
            # can block on Linux - before falling back to what it already had.
            # Candidate order protects the ambiguous case: 1048576 is tried
            # before its 4.63% near-miss 1000000, so a full reply wins first.
            if verbose:
                print(f"  · {b} answered the ID read; using it "
                      f"(no readable card at ports 0-1 idx 0)", flush=True)
            time.sleep(settle)
            try:
                ser = open_serial(port, b)
                ser.reset_input_buffer()
                ser.reset_output_buffer()
                return ser, b
            except Exception:
                return None, None
        time.sleep(settle)

    if fallback is None:
        return None, None
    if verbose:
        print(f"  · no rate returned a full reply; falling back to {fallback} "
              f"(large reads may be unreliable)", flush=True)
    try:
        ser = open_serial(port, fallback)
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        return ser, fallback
    except Exception:
        return None, None


def open_serial(port, baud):
    if sys.platform == "win32" and port.upper().startswith("COM"):
        port = f"\\\\.\\{port}"
    return serial.Serial(port, baud, timeout=0.1, write_timeout=2.0)


def main():
    ap = argparse.ArgumentParser(description="Read/set NovaStar LED brightness")
    default_port = "COM5" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=None,
                    help=f"force a baud; default auto-detects over {BAUD_CANDIDATES}")
    ap.add_argument("--ports", type=int, default=2, help="output ports to scan")
    ap.add_argument("--max-idx", type=int, default=127, help="max receiving-card index per port (chain length cap)")
    ap.add_argument("--gap", type=int, default=3, help="stop a port after this many consecutive missing cards")
    ap.add_argument("--set", type=float, metavar="PCT", help="set brightness percent (0-100), broadcast")
    ap.add_argument("--set-raw", type=int, metavar="N", help="set raw brightness (0-255), broadcast")
    ap.add_argument("--no-gains", action="store_true", help="don't re-send the default R/G/B gains on --set")
    ap.add_argument("--card", metavar="PORT:IDX", default=None,
                    help="read ONE card and stop (1-based port, as nova_cards.py "
                         "--walk prints it, e.g. --card 2:6). Works on a wall whose "
                         "controller answers past the end of a chain, where the "
                         "full scan is refused")
    ap.add_argument("--raw", action="store_true", help="print raw frames")
    args = ap.parse_args()

    try:
        if args.baud:
            ser, baud = open_serial(args.port, args.baud), args.baud
        else:
            ser, baud = detect_baud(args.port)
            if ser is None:
                # Never fall back to a guess: writing a brightness broadcast at the
                # wrong rate looks like it worked and silently does nothing.
                sys.exit(f"Nothing answered on {args.port} at any of "
                         f"{BAUD_CANDIDATES}.\n"
                         f"  Check the cable, and that NovaLCT/MonitorSite or the "
                         f"fleet client is not holding the port.\n"
                         f"  Force a rate with --baud if you know it.")
            print(f"  · auto-detected {baud} baud on {args.port}")
    except serial.SerialException as e:
        avail = [p.device for p in serial.tools.list_ports.comports()]
        sys.exit(f"Cannot open {args.port}: {e}\n  Available: {', '.join(avail) or 'none'}")

    try:
        if args.set is not None or args.set_raw is not None:
            seq = Seq()
            rawv = args.set_raw if args.set_raw is not None else pct_to_raw(args.set)
            rawv = set_brightness(ser, rawv, seq, with_gains=not args.no_gains, raw=args.raw)
            print(f"== set brightness -> {rawv} (0x{rawv:02x}, {raw_to_pct(rawv)}%) broadcast to all cards ==")

        print(f"== NovaStar brightness on {args.port} @ {baud} 8N1 ==")
        if args.card:
            # Read ONE named card and stop. On a controller that answers past the
            # end of a chain the scan below is refused (its count would be noise),
            # which left no way to read the cards that ARE real - take the index
            # from a nova_cards.py --walk, whose port numbers are 1-based too.
            try:
                _p, _i = (int(x) for x in args.card.split(":"))
            except ValueError:
                sys.exit("--card wants PORT:IDX with a 1-based port, e.g. --card 2:6")
            _p -= 1
            _seq = Seq()
            _blk = transact(ser, build_read(_seq.next(), 0x01, _p, _i, RX_BLOCK, 256),
                            args.raw)
            _geo = parse_geometry(_blk[0]["data"] if _blk else b"")
            _raw = read_brightness(ser, _p, _i, _seq, args.raw)
            _what = f"{_geo[0]}x{_geo[1]}" if _geo else "no geometry (not a card)"
            if _raw is None:
                print(f"  port {_p+1} card {_i}: {_what}, brightness read returned nothing")
                return 1
            print(f"  port {_p+1} card {_i}: {_what}, brightness "
                  f"{_raw:3d}/255  ({raw_to_pct(_raw)}%)")
            return 0
        # Same guard as led_report: a port answering at an impossible index means
        # the scan would count noise and walk every index. Cheap, and it stops
        # this tool hanging on such a wall.
        _seq = Seq()
        _echo = [p for p in range(args.ports)
                 if card_present(ser, p, args.max_idx + 50, _seq)]
        if _echo:
            print(f"  ! port(s) {', '.join(str(p+1) for p in _echo)} answer at index "
                  f"{args.max_idx + 50}, which cannot be a real card - the port "
                  f"replies for every index. Skipping the scan; its count would be "
                  f"noise.")
            return 1
        cards = scan_brightness(ser, args.ports, args.max_idx, gap=args.gap, raw=args.raw)
        if not cards:
            print("  no receiving cards responded (check port/baud/cable, panels on)")
            return 1
        for c in cards:
            if c["raw"] is None:
                print(f"  port {c['port']+1} card {c['idx']}: present, brightness read returned nothing")
            else:
                print(f"  port {c['port']+1} card {c['idx']}: brightness "
                      f"{c['raw']:3d}/255  ({raw_to_pct(c['raw'])}%)")
        return 0
    finally:
        ser.close()


if __name__ == "__main__":
    sys.exit(main())
