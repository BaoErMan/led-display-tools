#!/usr/bin/env python3
"""led_brightness.py - read NovaStar receiving-card brightness for the Fleet
Monitor client.

Design goals (see the discussion that led to this build):
  * NovaStar-only. It sends ONLY NovaStar frames (never a Huidu probe frame), so
    a machine that turns out to be Huidu - or has no LED hardware at all - simply
    gets no valid reply and soft-fails to an error dict. Huidu gear is never
    disturbed.
  * Read-only. It never writes brightness/gains; it only reads the R/W register.
  * Broadcast-authoritative. Brightness is global on NovaStar, so ONE real card
    gives the wall's value - no per-card scan, minimal serial traffic. "Real" is
    the load-bearing word: the card must answer with valid geometry (find_card),
    because an empty port echoes bytes that read as a plausible brightness.
  * Never raises. A busy port (operator running NovaLCT/MonitorSite), an absent
    port, or a missing dependency all return {"error": "..."}.

Returns on success:
    {"serial_port": "COM5", "vendor": "novastar", "raw": 0-255, "pct": 0-100}
Otherwise:
    {"error": "<reason>"}
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_NOVA = os.path.join(_HERE, "nova_probe_re")
for _p in (_HERE, _NOVA):
    if _p not in sys.path:
        sys.path.insert(0, _p)

CP210X_VID = 0x10C4     # Silicon Labs CP210x USB-UART bridge (NovaStar + Huidu)
CP210X_PID = 0xEA60

# Baud is NOT the same on every NovaStar card: one sending card runs 115200,
# another runs 1,000,000. Try the likely rates until one answers, then remember
# the winner per port so later reads skip straight to it.
# 1048576 (2^20) FIRST: that is what NovaStar sending cards such as the MCTRL600
# actually run at when the manual/NovaLCT says "1M". Probing 1000000 instead is a
# 4.63% mismatch - a UART resyncs each start bit, so by the stop bit the sampling
# point has drifted 44% of a bit, right at the 50% failure edge. Single-byte reads
# mostly survive; a 256-byte reply almost always takes a hit, arriving partial and
# misaligned, so POPULATED cards read as absent. 1000000 is kept for cards that
# genuinely use it, but must be tried AFTER the exact rate - a card at 1048576
# answers well enough at 1000000 to fool a probe.
BAUD_CANDIDATES = (115200, 1048576, 1000000, 921600)
_good_baud = {}         # serial_port -> baud that last produced a valid reply
_good_card = {}         # serial_port -> (port, idx) of a real receiving card


def _cp210x_ports():
    """All CP210x serial ports on this machine (the bridge NovaStar cards use)."""
    try:
        import serial.tools.list_ports
    except Exception:
        return []
    out = []
    for p in serial.tools.list_ports.comports():
        if getattr(p, "vid", None) == CP210X_VID and getattr(p, "pid", None) == CP210X_PID:
            out.append(p.device)
    return out


def _open(port, baud):
    import serial
    dev = port
    if sys.platform == "win32" and port.upper().startswith("COM"):
        dev = f"\\\\.\\{port}"
    return serial.Serial(dev, baud, timeout=0.1, write_timeout=2.0)


CLAMP_IDX = 177         # far past any real chain; what a port returns here is
                        # its "nothing at this index" answer (see nova_cards.py)
FIND_DEPTH = 16         # indices to walk per port looking for a real card
FIND_GAP = 3            # consecutive unparseable blocks that end a port


def _block(ser, port, idx, seq):
    from nova_probe import build_read, transact, RX_BLOCK
    reps = transact(ser, build_read(seq.next(), 0x01, port, idx, RX_BLOCK, 256))
    return reps[0]["data"] if reps else b""


def _clamp_digest(ser, port, seq):
    """Digest of what this port answers PAST the end of its chain, or None.

    A port with no cards does not go silent on every controller: an MCTRL300
    answers every index with a well-formed 240x100 block carrying valid geometry.
    Reading that index tells us what "no card here" looks like on this port, so
    the walk below can tell a real card from the filler."""
    import hashlib
    from nova_probe import parse_geometry
    data = _block(ser, port, CLAMP_IDX, seq)
    return hashlib.sha1(data).hexdigest()[:8] if parse_geometry(data) else None


def find_card_ex(ser, seq, ports=8, idxs=FIND_DEPTH, gap=FIND_GAP):
    """((port, idx), strong) of a REAL receiving card, or (None, False).

    `strong` is True when the block DIFFERS from what its port answers past the
    end of the chain - i.e. it cannot be filler. False means it parsed but equals
    that answer, which is normal on an MCTRL600 (whose clamp is the last real
    card's block) and is why such a card is still usable. The caller keeps the
    flag so a later re-check applies the same standard the choice was made by,
    instead of rejecting a card it just accepted.

    Cards are NOT always on port 0 / idx 0 - the chain can hang off any output
    port, and it need not start at index 0: on a live wall port 1 was empty and
    port 2 held four 240x80 cards at indices 6-9.

    Valid geometry is NOT sufficient to call something a card. Two failure modes
    have both been seen on live hardware:

      * an empty port echoes non-zero bytes with NO geometry (the old code's
        "first non-zero brightness byte" fallback settled on these);
      * an empty port answers EVERY index with a well-formed block that parses
        perfectly - an MCTRL300 returns 240x100 with params[10 16 255 255] at
        every index of an unused port, and at index 177 of a used one.

    The second is why geometry alone was not enough: two walls reported 11%
    (raw 28) on the dashboard, read from that filler block at port 0 index 0,
    while their real cards on port 2 were at 60%. Brightness is written as a
    BROADCAST and is global, so any REAL card gives the wall's value - but the
    filler is not a card and its byte is not brightness.

    So: learn each port's out-of-range answer first, then take the first index
    whose block parses AND differs from it. A block equal to the clamp is kept
    only as a last resort, because on an MCTRL600 the clamp IS the last real
    card's block - on a wall of identical panels every real card matches it, and
    refusing them would report nothing on a perfectly healthy wall.

    Returns None if nothing parses anywhere; the caller turns that into an error
    the dashboard omits, which beats a confident wrong number.
    """
    import hashlib
    from nova_probe import parse_geometry
    weak = None
    for p in range(ports):
        clamp = _clamp_digest(ser, p, seq)
        misses = 0
        for i in range(idxs):
            data = _block(ser, p, i, seq)
            if not parse_geometry(data):
                misses += 1
                if misses >= gap:
                    break                  # silent/garbage port, move on
                continue
            misses = 0
            if clamp is None or hashlib.sha1(data).hexdigest()[:8] != clamp:
                return (p, i), True        # differs from the filler: a real card
            if weak is None:
                weak = (p, i)              # equals the filler; only if nothing better
    return weak, False


def find_card(ser, seq, ports=8, idxs=FIND_DEPTH, gap=FIND_GAP):
    """(port, idx) of a real receiving card, or None. See find_card_ex."""
    return find_card_ex(ser, seq, ports, idxs, gap)[0]


def card_still_real(ser, card, seq, strong=True):
    """Does the cached (port, idx) still look like the card we chose?

    The cache was previously trusted until a read returned NOTHING, so a wrong
    pick survived every read that came back with any byte at all - i.e. for the
    client's whole lifetime, clearable only by a restart. Two 256-byte reads per
    interval are cheap next to reporting a wrong brightness for days.

    It must still parse. `strong` cards must also still differ from what the port
    answers past the end of its chain - one that now matches the filler has gone
    away (or was never real), so the caller re-scans. A card chosen WITHOUT that
    property is only re-checked for geometry, since demanding it now would reject
    the card every time on a wall where nothing can satisfy it."""
    import hashlib
    from nova_probe import parse_geometry
    data = _block(ser, card[0], card[1], seq)
    if not parse_geometry(data):
        return False
    if not strong:
        return True
    clamp = _clamp_digest(ser, card[0], seq)
    if clamp is None:
        return True                        # port gives no filler answer to compare
    return hashlib.sha1(data).hexdigest()[:8] != clamp


def read_brightness(port=None, baud=None):
    """Read NovaStar brightness. `port` forces a serial port (else every CP210x
    port is tried); `baud` forces a rate (else auto-detect from BAUD_CANDIDATES,
    remembering the winner per port). Reads from a real card (see find_card, since
    the chain may be on port 1/2, not 0/0). Never raises."""
    try:
        import serial  # noqa: F401  (import check + used via _open)
        from nova_probe import Seq, build_read, transact, TX_ID
        from nova_bright import read_brightness as _read_one, raw_to_pct
    except (Exception, SystemExit) as e:
        # nova_probe calls sys.exit() if pyserial is absent -> SystemExit, which
        # is NOT an Exception, so catch it explicitly and never let it escape.
        return {"error": f"dependency missing ({e}); need pyserial + the led_probe folder"}

    ports = [port] if port else _cp210x_ports()
    if not ports:
        return {"error": "no CP210x serial port found (NovaStar sending card not detected)"}

    last_err = None
    for p in ports:
        if baud:
            bauds = [baud]
        else:   # last-known-good rate for this port first, then the candidates
            bauds = list(dict.fromkeys(
                ([_good_baud[p]] if p in _good_baud else []) + list(BAUD_CANDIDATES)))
        for b in bauds:
            ser = None
            try:
                ser = _open(p, b)
                seq = Seq()
                # NovaStar-only handshake: read the sending-card ID. A checksum-
                # valid AA55 reply => NovaStar at this baud. Silence => wrong baud,
                # not NovaStar, port busy, or panels off.
                if not transact(ser, build_read(seq.next(), 0x00, 0, 0, TX_ID, 8)):
                    last_err = f"{p}@{b}: no NovaStar reply"
                    continue
                card = _good_card.get(p)          # (port, idx, strong)
                if card is not None and not card_still_real(ser, card[:2], seq,
                                                            card[2]):
                    _good_card.pop(p, None)       # cached card is no longer real
                    card = None
                if card is None:
                    found, strong = find_card_ex(ser, seq)
                    card = (found[0], found[1], strong) if found else None
                if card is None:
                    # NovaStar answered its ID read, but nothing on any port looks
                    # like a receiving card at this rate. Do not guess a value from
                    # an echoing port; try the next rate, then report the error.
                    last_err = (f"{p}@{b}: NovaStar replied but no receiving card "
                                f"returned valid geometry")
                    continue
                cp, ci = card[0], card[1]
                raw = _read_one(ser, cp, ci, seq)
                if raw is None:
                    _good_card.pop(p, None)       # stale mapping; re-find next time
                    last_err = f"{p}@{b}: NovaStar found but brightness read returned nothing"
                    continue
                _good_baud[p] = b                 # remember for next time
                _good_card[p] = card
                return {"serial_port": p, "baud": b, "vendor": "novastar",
                        "port": cp, "idx": ci, "verified": bool(card[2]),
                        "raw": int(raw), "pct": int(raw_to_pct(raw))}
            except Exception as e:
                last_err = f"{p}@{b}: {e}"
            finally:
                if ser is not None:
                    try:
                        ser.close()
                    except Exception:
                        pass
    return {"error": last_err or "no NovaStar card responded"}


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Read NovaStar receiving-card brightness (read-only)")
    ap.add_argument("--led-port", default=None, help="serial port (default: auto-detect CP210x)")
    ap.add_argument("--baud", type=int, default=None, help="serial baud (default: auto-detect)")
    args = ap.parse_args()
    res = read_brightness(port=args.led_port, baud=args.baud)
    if res.get("raw") is not None:
        print(f"{res['serial_port']}: {res['pct']}% (raw {res['raw']}/255, {res['vendor']}, "
              f"port{(res.get('port') or 0) + 1} idx{res.get('idx')}"
              + ("" if res.get("verified") else ", card NOT distinguishable from "
                                                "this port's out-of-range answer")
              + ")")
        raise SystemExit(0)
    print(res.get("error", "unknown error"))
    raise SystemExit(1)
