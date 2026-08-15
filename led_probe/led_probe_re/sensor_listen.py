#!/usr/bin/env python3
"""sensor_listen.py - read the standalone Huidu light sensor straight off its COM
port and watch the value change as you cover it. No USB capture, no sniffer.

For the THIRD sensor type: Huidu systems with no multifunction card, where the
sensor hangs off its own USB-serial COM port. If it streams readings on its own
(most such sensors do), this is all you need - open the port and look. Live
probing beat capture-correlation on the NovaStar sensor too.

If nothing arrives, the sensor is probably poll-driven: whatever Huidu app reads
it must send a request first, and that app also holds the port. In that case fall
back to capturing the USB traffic and use sensor_analyze.py.

    python sensor_listen.py --list                     # what COM ports exist?
    python sensor_listen.py --port COM5 --scan-bauds   # find the baud rate
    python sensor_listen.py --port COM5 --baud 9600    # raw timestamped log
    python sensor_listen.py --port COM5 --baud 9600 --watch
        ^ live view: cover the sensor and watch which byte moves

Nothing here ever writes to the port unless you pass --poll.
"""
import argparse
import sys
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

COMMON_BAUDS = [9600, 115200, 19200, 38400, 57600, 4800, 2400]

# A reading counts as settled once this many consecutive samples stay
# within this tolerance - the objective end of a 'hold until it
# plateaus' calibration step.
SETTLE_N, SETTLE_TOL = 4, 2


def list_ports():
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("no serial ports found")
        return
    print(f"== {len(ports)} serial port(s) ==")
    for p in ports:
        print(f"  {p.device:12} {p.description}")
        if p.hwid:
            print(f"               {p.hwid}")
    print("\n  The sensor is the one that is NOT the LED sending card.")


def open_port(port, baud, timeout=0.2):
    if sys.platform == "win32" and port.upper().startswith("COM"):
        port = f"\\\\.\\{port}"
    return serial.Serial(port, baud, timeout=timeout)


def _printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for c in b if 32 <= c < 127 or c in (10, 13)) / len(b)


def scan_bauds(port, seconds=3.0, poll=None):
    """Try each common baud and report what comes back, so you can pick the one
    that yields consistent data rather than framing noise."""
    print(f"== listening {seconds:.0f}s at each of {len(COMMON_BAUDS)} baud rates ==")
    print("  baud     bytes  printable  distinct  sample")
    best = []
    for b in COMMON_BAUDS:
        try:
            ser = open_port(port, b)
        except Exception as e:
            print(f"  {b:7}  cannot open: {e}")
            continue
        try:
            if poll:
                ser.write(poll)
                ser.flush()
            buf = bytearray()
            t0 = time.time()
            while time.time() - t0 < seconds:
                buf += ser.read(4096)
            n = len(buf)
            pr = _printable_ratio(buf)
            distinct = len(set(buf))
            print(f"  {b:7}  {n:6}  {pr:8.0%}  {distinct:8}  "
                  f"{bytes(buf[:16]).hex()}")
            if n:
                best.append((n, b))
        finally:
            ser.close()
    if not best:
        print("\n  Nothing arrived at any baud. The sensor is probably poll-driven")
        print("  (or the port is held by the Huidu app). Close that app and retry,")
        print("  or capture the USB traffic and use sensor_analyze.py.")
        return None
    best.sort(reverse=True)
    print(f"\n  most data at {best[0][1]} baud - try: --baud {best[0][1]} --watch")
    return best[0][1]


def log(port, baud, seconds, poll=None, interval=1.0):
    """Timestamped raw log. Cover/uncover the sensor while this runs."""
    ser = open_port(port, baud)
    limit = "until Ctrl-C" if seconds <= 0 else f"for {seconds:.0f}s"
    print(f"== logging {port} @ {baud} {limit} "
          f"(cover and uncover the sensor now) ==")
    t0 = time.time()
    try:
        while seconds <= 0 or time.time() - t0 < seconds:
            if poll:
                ser.write(poll)
                ser.flush()
            chunk = ser.read(4096)
            if chunk:
                print(f"  {time.time()-t0:7.2f}s  {len(chunk):4d}B  "
                      f"{chunk[:32].hex()}  "
                      f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk[:32])}")
            if poll:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("  stopped")
    finally:
        ser.close()


def watch(port, baud, seconds, reclen=None, poll=None, interval=1.0):
    """Live view: split the stream into fixed-size records and show, per byte
    offset, the current value and the range seen so far. Cover the sensor and the
    offset that moves is your reading."""
    ser = open_port(port, baud)
    print(f"== watching {port} @ {baud} - cover/uncover the sensor "
          f"(Ctrl-C to stop) ==\n")
    buf = bytearray()
    fstats = {}       # tag -> (min, max)
    ostats = {}       # byte offset -> (min, max), only for non-field streams
    announced = False
    t0 = time.time()
    last_rec = [None]
    nrecs = [0]
    hist = {}
    print("  Press ENTER to mark an event (e.g. 'covered' / 'uncovered').\n")

    def _marker():
        # Marking matters here: this sensor updates slowly, so you cannot line
        # readings up with what you did from timestamps alone.
        for line in sys.stdin:
            print(f"  ----- MARK {time.time()-t0:6.1f}s: "
                  f"{line.strip() or 'event'} -----")
    try:
        import threading
        threading.Thread(target=_marker, daemon=True).start()
    except Exception:
        pass
    try:
        while seconds <= 0 or time.time() - t0 < seconds:
            if poll:
                ser.write(poll)
                ser.flush()
            buf += ser.read(4096)
            recs, buf = split_records(bytes(buf))
            buf = bytearray(buf)
            for rec in recs:
                if reclen and len(rec) != reclen:
                    continue
                fields = parse_fields(rec)
                if not announced:
                    announced = True
                    print(f"  ({len(rec)}B records, "
                          f"{'tagged fields: ' + ' '.join(sorted(fields)) if fields else 'raw bytes'})\n")
                if fields:
                    for tag, v in fields.items():
                        lo, hi = fstats.get(tag, (v, v))
                        fstats[tag] = (min(lo, v), max(hi, v))
                    now = time.time() - t0
                    gap = "" if last_rec[0] is None else f" (+{now-last_rec[0]:4.1f}s)"
                    last_rec[0] = now
                    nrecs[0] += 1
                    # Track the field that moves most - that's the reading - and
                    # say when it has stopped moving, so a "hold until it
                    # plateaus" test has an objective end rather than a guess.
                    for tag, v in fields.items():
                        hist.setdefault(tag, []).append(v)
                        del hist[tag][:-SETTLE_N]
                    main = max(fstats, key=lambda t: fstats[t][1] - fstats[t][0])
                    h = hist.get(main, [])
                    settled = (len(h) >= SETTLE_N and max(h) - min(h) <= SETTLE_TOL)
                    note = (f"   SETTLED at {main}={h[-1]}" if settled
                            else f"   ({main} still moving)" if len(h) >= 2 else "")
                    cells = "  ".join(
                        f"{t}={v:4d}[{fstats[t][0]}-{fstats[t][1]}]"
                        for t, v in fields.items())
                    print(f"  {now:6.1f}s{gap}  {cells}{note}")
                else:
                    for o, v in enumerate(rec):
                        lo, hi = ostats.get(o, (v, v))
                        ostats[o] = (min(lo, v), max(hi, v))
                    moving = sorted(((hi - lo, o) for o, (lo, hi) in ostats.items()),
                                    reverse=True)[:4]
                    cells = "  ".join(f"off{o}={rec[o]:3d}[{ostats[o][0]}-{ostats[o][1]}]"
                                      for _s, o in moving if _s > 0)
                    print(f"  {time.time()-t0:6.1f}s  {rec[:12].hex():<24} {cells}")
            if poll:
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        ser.close()

    if fstats:
        print("\n== fields, by how much they moved ==")
        for tag, (lo, hi) in sorted(fstats.items(), key=lambda kv: -(kv[1][1] - kv[1][0])):
            mark = "   <-- varies" if (hi - lo) >= 8 else "   (constant/near-constant)"
            print(f"  {tag}: {lo:5d}..{hi:5d}  spread {hi-lo:5d}{mark}")
        if last_rec[0] and nrecs[0] > 1:
            rate = last_rec[0] / max(1, nrecs[0] - 1)
            print(f"\n  update interval ~{rate:.1f}s ({nrecs[0]} readings in "
                  f"{last_rec[0]:.0f}s)")
            if rate > 3:
                print(f"  SLOW SENSOR: hold each state for at least {rate*4:.0f}s")
                print("  so several readings land in it - short cover/uncover")
                print("  cycles alias badly and prove nothing.")
        print("\n  Direction is what confirms it: the field must DROP while covered")
        print("  and RECOVER when uncovered. A slow monotonic drift is ambient")
        print("  light changing, not your hand.")
    elif ostats:
        moving = sorted(((hi - lo, o) for o, (lo, hi) in ostats.items()), reverse=True)
        print("\n== byte offsets by how much they moved ==")
        for spread, o in moving[:8]:
            lo, hi = ostats[o]
            print(f"  off {o:3d}: {lo:3d}..{hi:3d}  spread {spread:3d}")


def is_line_framed(buf):
    """True if the stream is delimited by CR/LF rather than fixed-length records.

    Checked FIRST, because guessing a fixed record length on a line-framed stream
    misaligns every record and then *every* byte offset looks like it is moving -
    which reads exactly like a sensor signal and is entirely an artifact."""
    return b"\n" in buf or b"\r" in buf


def split_records(buf):
    """(records, remainder). Line-framed if possible, else fixed-length."""
    if is_line_framed(buf):
        parts = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
        return [p for p in parts[:-1] if p], parts[-1]
    n = _guess_reclen(buf)
    if not n:
        return [], buf
    end = (len(buf) // n) * n
    return [buf[i:i + n] for i in range(0, end, n)], buf[end:]


FIELD_RE = None


def parse_fields(rec):
    """Tokenise a record like b'\\xc9S01P7DV0E2v0E2' into {'S':1,'P':125,...}.

    Generic on purpose: any run of letters followed by hex digits becomes a
    field, so this reads the format without it being hard-coded. Case matters -
    'V' and 'v' are different fields."""
    global FIELD_RE
    if FIELD_RE is None:
        import re
        FIELD_RE = re.compile(rb"([A-Za-z])([0-9A-Fa-f]+)")
    text = bytes(rec)
    out = {}
    for m in FIELD_RE.finditer(text):
        tag = m.group(1).decode()
        try:
            out[tag] = int(m.group(2), 16)
        except ValueError:
            continue
    return out


def _guess_reclen(buf):
    """Fixed-length fallback: if a byte value recurs at a constant period, use it."""
    for n in range(2, 65):
        if len(buf) < n * 4:
            break
        if all(buf[i] == buf[0] for i in range(0, n * 4, n)):
            return n
    return 0


def main():
    ap = argparse.ArgumentParser(description="Read a Huidu light sensor off its COM port")
    ap.add_argument("--list", action="store_true", help="list serial ports")
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--scan-bauds", action="store_true")
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--seconds", type=float, default=0.0,
                    help="0 = run until Ctrl-C (the default); set a limit only "
                         "if you want one")
    ap.add_argument("--reclen", type=int, default=None,
                    help="bytes per reading, if you already know it")
    ap.add_argument("--poll", default=None,
                    help="hex bytes to send before each read, if the sensor is "
                         "poll-driven (e.g. 01 03 00 00 00 01 84 0a)")
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()

    if args.list or not args.port:
        list_ports()
        if not args.port:
            print("\n  then: sensor_listen.py --port COMx --scan-bauds")
        return 0

    poll = bytes.fromhex(args.poll.replace(" ", "")) if args.poll else None
    try:
        if args.scan_bauds:
            scan_bauds(args.port, poll=poll)
        elif args.watch:
            watch(args.port, args.baud, args.seconds, args.reclen, poll, args.interval)
        else:
            log(args.port, args.baud, args.seconds, poll, args.interval)
    except serial.SerialException as e:
        sys.exit(f"Cannot open {args.port}: {e}\n"
                 f"  If the Huidu app is running it holds the port - close it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
