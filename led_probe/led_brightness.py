#!/usr/bin/env python3
"""led_brightness.py - read NovaStar receiving-card brightness for the Fleet
Monitor client.

Design goals (see the discussion that led to this build):
  * NovaStar-only. It sends ONLY NovaStar frames (never a Huidu probe frame), so
    a machine that turns out to be Huidu - or has no LED hardware at all - simply
    gets no valid reply and soft-fails to an error dict. Huidu gear is never
    disturbed.
  * Read-only. It never writes brightness/gains; it only reads the R/W register.
  * Broadcast-authoritative. Brightness is global on NovaStar, so a single read
    at (port 0, index 0) is the real value - no per-card scan, minimal serial
    traffic, no phantom-card noise.
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


def find_card(ser, seq, ports=8, idxs=2):
    """Return (port, idx) of a REAL receiving card. Cards are NOT always on
    port 0 / idx 0 - the chain can hang off any output port (2-, 4-, 8-port
    sending cards exist), and an empty port echoes non-zero bytes with NO
    geometry and brightness 0. So scan the ports and prefer the first card whose
    config block yields valid geometry; fall back to the first port/idx reporting
    non-zero brightness; else (0, 0). Returns on the first hit, so a low-port card
    is cheap; only a fully empty/off wall scans everything."""
    from nova_probe import build_read, transact, RX_BLOCK, parse_geometry
    from nova_bright import BRIGHT_REG
    fallback = None
    for p in range(ports):
        for i in range(idxs):
            reps = transact(ser, build_read(seq.next(), 0x01, p, i, RX_BLOCK, 256))
            data = reps[0]["data"] if reps else b""
            if parse_geometry(data):
                return (p, i)
            if fallback is None:
                br = transact(ser, build_read(seq.next(), 0x01, p, i, BRIGHT_REG, 1))
                if br and br[0]["data"] and br[0]["data"][0] > 0:
                    fallback = (p, i)
    return fallback or (0, 0)


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
                cp, ci = _good_card.get(p) or find_card(ser, seq)  # cached, else scan
                raw = _read_one(ser, cp, ci, seq)
                if raw is None:
                    _good_card.pop(p, None)       # stale mapping; re-find next time
                    last_err = f"{p}@{b}: NovaStar found but brightness read returned nothing"
                    continue
                _good_baud[p] = b                 # remember for next time
                _good_card[p] = (cp, ci)
                return {"serial_port": p, "baud": b, "vendor": "novastar",
                        "port": cp, "idx": ci,
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
              f"port{res.get('port')} idx{res.get('idx')})")
        raise SystemExit(0)
    print(res.get("error", "unknown error"))
    raise SystemExit(1)
