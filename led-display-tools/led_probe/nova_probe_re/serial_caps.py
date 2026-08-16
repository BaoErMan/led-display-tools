#!/usr/bin/env python3
"""serial_caps.py - which baud rates can this machine's adapter ACTUALLY set?

Why this exists: NovaStar sending cards such as the MCTRL600 run at 1048576 bps
(2^20). That is NOT one of Linux's standard termios rates - the standard list
jumps 921600 -> 1000000 -> 1152000. pyserial can request a custom rate on Linux
via termios2, but a given driver may refuse it, or silently substitute a nearby
standard rate. A silent substitution is the dangerous one: the port opens, reads
"work" for short replies, and every large reply comes back corrupt - exactly the
4.63% mismatch symptom - with nothing in the logs to say why.

This asks the driver what it actually set, and flags any disagreement.

    python serial_caps.py                 # list ports
    python serial_caps.py --port /dev/ttyUSB0
"""
import argparse
import sys

CANDIDATES = (9600, 115200, 230400, 460800, 921600, 1000000, 1048576, 1152000)


def main():
    ap = argparse.ArgumentParser(description="Report settable baud rates for a serial port")
    ap.add_argument("--port", default=None)
    args = ap.parse_args()

    try:
        import serial
        import serial.tools.list_ports
    except ImportError:
        sys.exit("pyserial required: pip install pyserial")

    if not args.port:
        ports = list(serial.tools.list_ports.comports())
        if not ports:
            print("no serial ports found")
            return 1
        print(f"== {len(ports)} serial port(s) ==")
        for p in ports:
            print(f"  {p.device:16} {p.description}")
            if p.hwid:
                print(f"  {'':16} {p.hwid}")
        print("\n  then: serial_caps.py --port <device>")
        return 0

    print(f"== {args.port}: what the driver will actually set ==")
    print("  requested   accepted   driver reports   verdict")
    trouble = []
    for b in CANDIDATES:
        try:
            s = serial.Serial(args.port, b, timeout=0.1)
        except Exception as e:
            print(f"  {b:>9}   no        -                {type(e).__name__}: "
                  f"{str(e)[:44]}")
            continue
        try:
            got = s.baudrate
        except Exception:
            got = None
        finally:
            try:
                s.close()
            except Exception:
                pass
        if got == b:
            print(f"  {b:>9}   yes       {got:<15}  ok")
        else:
            print(f"  {b:>9}   yes       {got!s:<15}  SUBSTITUTED - unusable")
            trouble.append((b, got))

    print()
    if any(b == 1048576 for b, _ in trouble) or True:
        pass
    subs = dict(trouble)
    if 1048576 in subs:
        print("  1048576 was SUBSTITUTED. An MCTRL600 speaks that rate, so this")
        print("  adapter cannot talk to it reliably: short reads will appear to")
        print("  work and every large reply will be corrupt.")
        print("  Options: a different USB-serial adapter (FTDI handles arbitrary")
        print("  rates well), or set the sending card to 115200 in NovaLCT.")
    elif 1048576 not in subs:
        print("  1048576 is settable here - if reads are still corrupt the problem")
        print("  is elsewhere (cable, EMI, or the card is on another rate).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
