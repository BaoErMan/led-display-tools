#!/usr/bin/env python3
"""nova_sensor.py - Read the NovaStar ambient LIGHT SENSOR over the CP210x link.

Reverse-engineered from an ataradov capture of NovaLCT's light-sensor / auto-
brightness screen (brightness/LIGHTDARK.pcapng). The screen does a tiny exchange
on the sending card (dev=0x00):

    wr  reg=00 3f 00 00 02  data=3c     # trigger/select the sensor read
    rd  reg=00 0f 00 00 02  len=2  ->    # 2-byte ambient value (0x0080 in the dark)

This tool replays that exchange and prints the raw value. Use --watch to poll
continuously so you can cover/uncover the sensor and watch it move (that's how we
confirm which byte / scale is the light reading, since the capture only had the
dark value). --no-trigger skips the 003f write to test if 000f reads standalone.

Usage:
    python nova_sensor.py --port /dev/ttyUSB0
    python nova_sensor.py --port /dev/ttyUSB0 --watch      # live, cover/uncover it
    python nova_sensor.py --port /dev/ttyUSB0 --no-trigger --watch
    python nova_sensor.py --port /dev/ttyUSB0 --raw        # show frames
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

from nova_probe import (Seq, build_read, build_write, transact,   # noqa: E402
                        DEFAULT_BAUD)

# from the LIGHTDARK capture (dev=0x00 sending card)
TRIG_REG = bytes([0x00, 0x3f, 0x00, 0x00, 0x02])   # write to select/trigger
TRIG_DATA = bytes([0x3c])                           # payload NovaLCT sent
SENS_REG = bytes([0x00, 0x0f, 0x00, 0x00, 0x02])   # read: 2-byte sensor value


def read_sensor(ser, seq, trigger=True, raw=False):
    """Do NovaLCT's write-then-read and return the raw 2-byte value (bytes) or None."""
    if trigger:
        transact(ser, build_write(seq.next(), 0x00, 0, 0, TRIG_REG, TRIG_DATA), raw)
    reps = transact(ser, build_read(seq.next(), 0x00, 0, 0, SENS_REG, 2), raw)
    if reps and len(reps[0]["data"]) >= 2:
        return reps[0]["data"][:2]
    return None


def decode(v):
    """Decode the 2-byte reply. Value is little-endian uint16 where bit 15 is a
    'sensor present/valid' flag and the low 15 bits are the light level (~lux):
    covered -> 0, dim room -> tens, bright spot -> ~1200 (verified live)."""
    le = int.from_bytes(v, "little")
    return {"valid": bool(le & 0x8000), "lux": le & 0x7FFF, "raw": v.hex()}


def describe(v):
    d = decode(v)
    flag = "" if d["valid"] else "  [sensor DISCONNECTED]"
    return f"light ~{d['lux']:5d} lux   (raw={d['raw']}){flag}"


def open_serial(port, baud):
    if sys.platform == "win32" and port.upper().startswith("COM"):
        port = f"\\\\.\\{port}"
    return serial.Serial(port, baud, timeout=0.1, write_timeout=2.0)


def main():
    ap = argparse.ArgumentParser(description="Read NovaStar ambient light sensor")
    default_port = "COM5" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--watch", action="store_true", help="poll continuously (Ctrl-C to stop)")
    ap.add_argument("--interval", type=float, default=0.5, help="--watch poll interval (s)")
    ap.add_argument("--no-trigger", action="store_true", help="skip the 003f write, just read 000f")
    ap.add_argument("--raw", action="store_true", help="print raw frames")
    args = ap.parse_args()

    try:
        ser = open_serial(args.port, args.baud)
    except serial.SerialException as e:
        avail = [p.device for p in serial.tools.list_ports.comports()]
        sys.exit(f"Cannot open {args.port}: {e}\n  Available: {', '.join(avail) or 'none'}")

    seq = Seq()
    trig = not args.no_trigger
    try:
        if not args.watch:
            v = read_sensor(ser, seq, trigger=trig, raw=args.raw)
            if v is None:
                print("  no sensor reply (check port/cable; is a light sensor attached?)")
                return 1
            print(f"  light sensor: {describe(v)}")
            return 0

        print(f"== watching light sensor on {args.port} (trigger={'on' if trig else 'off'}); "
              f"cover/uncover it. Ctrl-C to stop ==")
        while True:
            v = read_sensor(ser, seq, trigger=trig, raw=args.raw)
            ts = time.strftime("%H:%M:%S")
            print(f"  {ts}  " + (describe(v) if v else "(no reply)"))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
    finally:
        ser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
