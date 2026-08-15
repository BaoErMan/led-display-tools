#!/usr/bin/env python3
"""provision_wall.py - commission one LED wall for the fleet client, in one step.

Detects the vendor, obtains a brightness template if the wall is Huidu, and
records a fingerprint so that template can never be applied to a different wall.
NovaStar walls need no template and are reported as ready immediately.

    # Huidu, from HDset's own config (preferred - no capture, no sniffer):
    #   a screen-config export - .sss (newer HDset) or .ssx (older) - or
    #   net_default_new.xml. Verified working on all three:
    python provision_wall.py --port COM8 --config wall_x.sss

    # Huidu, from a USB capture (only if no config file holds the block):
    python provision_wall.py --port COM8 --capture set_100.pcapng

    # NovaStar, or just to see what a wall is:
    python provision_wall.py --port COM8

Writes <outdir>/<name>.bin and <outdir>/<name>.bin.wall.json.

Why the fingerprint matters: a Huidu brightness command carries that wall's whole
screen configuration - EDID, timings and display geometry. Two walls' blocks were
compared and 7 bytes of geometry differ outside the brightness field, so applying
one wall's template to another would rewrite its configuration. The fingerprint is
the guard, and this script always records one.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Works from the client bundle (modules under led_probe/) and from the research
# tree (modules beside this file), so the same script serves both.
for sub in ("", "led_probe", "led_probe_re", "nova_probe_re", "runtime",
            os.path.join("led_probe", "led_probe_re"),
            os.path.join("led_probe", "nova_probe_re")):
    d = os.path.join(HERE, sub) if sub else HERE
    if os.path.isdir(d) and d not in sys.path:
        sys.path.insert(0, d)


def main():
    ap = argparse.ArgumentParser(description="Commission one LED wall")
    default_port = "COM8" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port, help="serial port of the wall")
    ap.add_argument("--baud", type=int, default=None)
    ap.add_argument("--config", metavar="CFG|DIR",
                    help="HDset config for THIS wall: a screen-config export - "
                         ".sss (newer HDset) or .ssx (older) - or net_default_new.xml "
                         "/ net_default.xml, OR a folder to auto-scan for the block")
    ap.add_argument("--capture", metavar="PCAP",
                    help="USB capture of HDset pressing Send on THIS wall")
    ap.add_argument("--name", default="wall",
                    help="base name for the template files (default: wall)")
    ap.add_argument("--outdir", default=os.path.join(HERE, "walls"))
    ap.add_argument("--max-cards", type=int, default=64,
                    help="how far along the receiving-card chain to probe when "
                         "recording the fingerprint")
    ap.add_argument("--gap", type=int, default=3,
                    help="stop probing after this many consecutive silent indices")
    ap.add_argument("--no-fingerprint", action="store_true",
                    help="skip the fingerprint (NOT recommended - it is what stops "
                         "a template reaching the wrong wall)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    tpl_path = os.path.join(args.outdir, f"{args.name}.bin")

    # 1. Template, if a source was given.
    if args.config or args.capture:
        from hd_bright import extract_template_from_config, extract_template
        print("== 1. template ==")
        if args.config:
            cfg = args.config
            if os.path.isdir(cfg):
                from find_config import iter_files, scan_file
                print(f"  scanning {cfg} for a file that holds the block…")
                cfg = next((f for f in iter_files(cfg) if scan_file(f)[0]), None)
                if not cfg:
                    sys.exit("  no HDset file with a sending-card block under that "
                             "folder.\n  In HDset, Send the Sending-Card Parameters "
                             "first, or use the capture route (--capture).")
                print(f"  found block in {cfg}")
            extract_template_from_config(cfg, tpl_path)
        else:
            extract_template(args.capture, tpl_path)
    else:
        print("== 1. template: none requested ==")
        tpl_path = None

    # 2. Identify the wall on the port.
    print("\n== 2. vendor ==")
    from led_control import NovaLink, HdLink
    nova = NovaLink(port=args.port, baud=args.baud)
    if nova.connect():
        print(f"  NovaStar on {nova.port} @ {nova.baud} - no template needed")
        nova.close()
        print("\n== READY (NovaStar) ==")
        return 0
    hd = HdLink(port=args.port, baud=args.baud, template=tpl_path)
    if not hd.probe_only():
        print(f"  no LED controller answered on {args.port}")
        print("  check the cable, and close HDset - it holds the port")
        return 1
    print(f"  Huidu on {hd.port} @ {hd.baud}")

    try:
        # 3. Fingerprint - bind the template to this specific wall.
        if tpl_path and not args.no_fingerprint:
            print("\n== 3. fingerprint ==")
            from hd_bright import save_fingerprint, fingerprint_path
            fp = save_fingerprint(hd.ser, tpl_path, args.max_cards, args.gap)
            if not fp:
                print("  no receiving cards answered - fingerprint NOT saved.")
                print("  The template will still work but cannot be checked "
                      "against the wall; re-run when the cards are powered.")
            else:
                for c in fp:
                    print(f"  card {c['index']}: {c['width']}x{c['height']}")
                print(f"  -> {fingerprint_path(tpl_path)}")
        elif not tpl_path:
            print("\n  NO TEMPLATE. A Huidu wall cannot be driven without one.")
            print("  Re-run with --config <wall.sss / wall.ssx / net_default_new.xml> or")
            print("  --capture <pcap>.")
            return 1
    finally:
        hd.close()

    print(f"\n== READY (Huidu) ==\n  template : {tpl_path}")
    print(f"  point the client at it, e.g.  --hd-template {tpl_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
