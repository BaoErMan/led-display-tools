#!/usr/bin/env python3
"""
led_probe.py - One probe to identify and read receiving cards from EITHER a
Huidu (HDset) or a NovaStar (NovaLCT) sending card over the CP210x serial link.

It auto-detects the controller family with led_vendor's frame fingerprint, then
dispatches to the matching reader (hd_probe / nova_probe, imported from their
sibling directories). Use --vendor to force a family and skip detection.

Usage:
    python led_probe.py --port /dev/ttyUSB0
    python led_probe.py --port COM10 --vendor huidu --cards 2
    python led_probe.py --port /dev/ttyUSB0 --vendor novastar --ports 2
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "led_probe_re"))
sys.path.insert(0, os.path.join(HERE, "nova_probe_re"))

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

import hd_probe as HD          # noqa: E402  Huidu probe
import nova_probe as NV        # noqa: E402  NovaStar probe

DEFAULT_BAUD = 115200


def read_huidu(ser, n_cards, raw=False):
    rx = HD.run_probe(ser, n_cards=n_cards)
    cfgs = {}
    for payload, _ in HD.deframe(rx):
        if payload and payload[0] == 0x03:
            c = HD.parse_config(payload)
            cfgs[c["index"]] = c
    print("== Huidu controller ==")
    found = 0
    for i in range(n_cards):
        c = cfgs.get(i)
        if c:
            found += 1
            print(f"  slot {i}: receiving card present  {c['width']}x{c['height']}")
        else:
            print(f"  slot {i}: absent")
    print(f"== {found} receiving card(s) ==")
    return found


def read_nova(ser, ports, raw=False):
    print("== NovaStar controller ==")
    res = NV.scan_cards(ser, ports, raw=raw)
    NV.print_scan(res)
    return len(res["cards"])


def open_serial(port, baud):
    if sys.platform == "win32" and port.upper().startswith("COM"):
        port = f"\\\\.\\{port}"
    return serial.Serial(port, baud, bytesize=serial.EIGHTBITS,
                         parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                         timeout=0.1, write_timeout=2.0)


def main():
    ap = argparse.ArgumentParser(description="Unified Huidu/NovaStar receiving-card probe")
    default_port = "COM10" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--vendor", choices=("auto", "huidu", "novastar"), default="auto",
                    help="force a controller family (default: auto-detect)")
    ap.add_argument("--cards", type=int, default=4,
                    help="Huidu: receiving-card slots to probe (default 4)")
    ap.add_argument("--ports", type=int, default=2,
                    help="NovaStar: sending-card output ports to scan (default 2)")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    try:
        ser = open_serial(args.port, args.baud)
    except serial.SerialException as e:
        avail = [p.device for p in serial.tools.list_ports.comports()]
        sys.exit(f"Cannot open {args.port}: {e}\n  Available: {', '.join(avail) or 'none'}")

    try:
        fam = args.vendor
        if fam == "auto":
            fam = NV.whoami(ser)              # sends only harmless read/probe frames
            print(f"== detected: {fam} controller on {args.port} @ {args.baud} 8N1 ==")
        if fam == "novastar":
            n = read_nova(ser, args.ports, args.raw)
        elif fam == "huidu":
            n = read_huidu(ser, args.cards, args.raw)
        else:
            print(f"{args.port}: could not identify controller (no response). "
                  f"Check baud/cable, or force with --vendor.")
            return 1
    finally:
        ser.close()
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
