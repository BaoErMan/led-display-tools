#!/usr/bin/env python3
"""read_card.py - read ONE NovaStar card's brightness by (port, idx).

Save next to the led_probe folder and run from there. Ports are 1-BASED, the
way nova_cards.py --walk prints them:

    python read_card.py COM3 2:6        # the real 240x80 card
    python read_card.py COM3 1:0        # what the dashboard reads
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (os.path.join(HERE, "led_probe"),
          os.path.join(HERE, "led_probe", "nova_probe_re")):
    if os.path.isdir(p):
        sys.path.insert(0, p)

from nova_probe import Seq, build_read, transact, RX_BLOCK, parse_geometry
from nova_bright import read_brightness, raw_to_pct, open_serial, detect_baud

if len(sys.argv) < 3:
    sys.exit(__doc__)
port_name, spec = sys.argv[1], sys.argv[2]
p, i = (int(x) for x in spec.split(":"))
p -= 1                                    # 1-based on the command line

baud = int(sys.argv[3]) if len(sys.argv) > 3 else None
if baud:
    ser = open_serial(port_name, baud)
else:
    ser, baud = detect_baud(port_name)
    if ser is None:
        sys.exit(f"nothing answered on {port_name}")
print(f"== {port_name} @ {baud} ==")
try:
    seq = Seq()
    blk = transact(ser, build_read(seq.next(), 0x01, p, i, RX_BLOCK, 256))
    geo = parse_geometry(blk[0]["data"] if blk else b"")
    raw = read_brightness(ser, p, i, seq)
    what = f"{geo[0]}x{geo[1]}" if geo else "no geometry (not a card)"
    if raw is None:
        print(f"  port {p+1} card {i}: {what}, brightness read returned nothing")
    else:
        print(f"  port {p+1} card {i}: {what}, brightness {raw:3d}/255  ({raw_to_pct(raw)}%)")
finally:
    ser.close()
