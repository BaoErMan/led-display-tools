#!/usr/bin/env python3
"""hd_bright.py - set Huidu LED brightness (and the auto-brightness flag) over the
CP210x serial link, reverse-engineered from HDset captures. See PROTOCOL.md.

Brightness command (class 0x02 / sub 0x00, 521-byte payload = 9-byte header + 512
data). Pressing Send in HDset emits exactly ONE such frame - a full screen-config
block with the level embedded in it, not a small targeted command:

    payload[22]              auto-brightness: 0x00 = manual, 0x01 = auto (hardware)
    payload[58,60,62,64]     level as a direct 0-100 percent
    payload[59,61,63,65]     same level as pct*128//100 (floor)

Four (percent, scaled) channel pairs, all driven together by the master slider.

Because the command carries the WHOLE config block (EDID, timings, geometry), the
only safe way to send it is patch-and-replay: start from a frame captured on THAT
wall, overwrite the level bytes, recompute the CRC32.

  ** A template from a different wall would push that wall's entire screen **
  ** configuration onto this one. Templates are per-wall. Never share them.  **

The card replies with a 25-byte class-0x01 ACK that does NOT echo the brightness,
so there is no readback path - `read_brightness` is not implemented (see
PROTOCOL.md "Not yet decoded").

Usage:
    python hd_bright.py --set 75                       # 75%, manual
    python hd_bright.py --set 75 --port COM10          # Windows
    python hd_bright.py --auto                         # hand control back to hardware
    python hd_bright.py --set 40 --dry-run             # show the frame, send nothing
    python hd_bright.py --extract-template set_100.pcapng   # rebuild the template
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hd_probe import build_frame, deframe, open_serial, DEFAULT_BAUD  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TEMPLATE = os.path.join(HERE, "brightness_template.bin")

BRIGHT_CLASS, BRIGHT_SUB = 0x02, 0x00
AUTO_OFF = 22                       # 0x00 manual, 0x01 auto (hardware ambient loop)
PCT_OFFS = (58, 60, 62, 64)         # direct 0-100 percent
SCALED_OFFS = (59, 61, 63, 65)      # pct*128//100
FRAME_LEN = 521
HEADER_LEN_ = 9        # 9-byte header + 512 data = 521

# (sub, target) of a class-0x01 query that would read the sending-card block back
# from the hardware. It stays None: there is NO such query - a settled negative,
# do not go hunting again. HDset's Sending Card Parameters screen sends ZERO bytes
# when opened (it draws from local config), a 256-query sweep of sub 1 x target
# 0-255 returned nothing, and neither class-0x03 readback carries the EDID or
# brightness bytes. It does not matter: the template comes from HDset's saved
# config (--from-config, a .sss/.ssx/xml export), which is a better source anyway.
# acquire_template() below performs no I/O while this is None.
TEMPLATE_QUERY = None

# ---- HD-Y1 auto-brightness range (a DIFFERENT block from brightness) -------- #
# The multifunction card's ambient loop is clamped to a configured min%/max%.
# Those live in class 0x02 / sub 0x01 aimed at target 0x78 (the HD-Y1), NOT in the
# sending-card block that carries brightness - offsets 457/458 there are display
# geometry. Decoded from change_auto/set_max_only captures; the two writes differ
# at exactly offset 458 when only max was changed, so patch-and-replay is exact.
AUTO_SUB, AUTO_TARGET = 0x01, 0x78
AUTO_MIN_OFF, AUTO_MAX_OFF = 457, 458
# Read-only poll of the HD-Y1 (same query hd_auto_readback.py uses): class 0x01 /
# sub 0x01 / target 0x78 -> a 521-byte class-0x03 reply whose offset 18 is the LIVE
# auto brightness OUTPUT (%, clamped to min..max) and offset 15 the live light.
AUTO_READ_QUERY = bytes([0x01, 0x01, 0x00, 0x78, 0x01, 0, 0, 0, 0x10]) + b"\x00" * 16
AUTO_LIGHT_OFF, AUTO_OUTPUT_OFF = 15, 18
# The auto-range block is GENERIC across walls - verified 2026-08-08: a block
# captured on one wall set the range on a DIFFERENT wall and read back correctly.
# So unlike the brightness template this one ships as a fleet default and needs no
# per-wall capture. It is the SPARSE capture (36 non-zero bytes); another wall's
# had 335 more bytes of leaked HDset buffer that the card simply ignores.
DEFAULT_AUTO_TEMPLATE = os.path.join(HERE, "default_auto.bin")


def pct_to_scaled(pct):
    """The 0-128 companion byte. FLOOR, not round: 20 -> 25 and 60 -> 76 in the
    captures, whereas rounding would give 26 and 77."""
    return max(0, min(128, int(pct) * 128 // 100))


def load_template(path=DEFAULT_TEMPLATE):
    """The captured class-0x02 payload for THIS wall (521 bytes, no preamble/CRC)."""
    with open(path, "rb") as f:
        p = f.read()
    if len(p) != FRAME_LEN or p[0] != BRIGHT_CLASS or p[1] != BRIGHT_SUB:
        raise ValueError(
            f"{path}: expected a {FRAME_LEN}-byte class "
            f"0x{BRIGHT_CLASS:02x}/sub 0x{BRIGHT_SUB:02x} payload, got {len(p)} bytes "
            f"class 0x{p[0]:02x}/sub 0x{p[1]:02x}")
    return p


def build_brightness_payload(template, pct=None, auto=None):
    """Patch a template: `pct` 0-100 sets the level, `auto` True/False sets the
    hardware auto-brightness flag. Either may be None to leave it untouched
    (HDset keeps the last level when switching to auto)."""
    p = bytearray(template)
    if pct is not None:
        pct = max(0, min(100, int(round(pct))))
        scaled = pct_to_scaled(pct)
        for o in PCT_OFFS:
            p[o] = pct
        for o in SCALED_OFFS:
            p[o] = scaled
    if auto is not None:
        p[AUTO_OFF] = 0x01 if auto else 0x00
    return bytes(p)


def read_reply(ser, idle=0.25, timeout=1.5):
    """Read the card's ACK. Reuses hd_probe's pacing discipline: the card drops
    replies if you blast frames back-to-back, so always drain before sending
    the next one."""
    import time
    buf = bytearray()
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        chunk = ser.read(4096)
        if chunk:
            buf += chunk
            last = time.time()
        elif last is not None and time.time() - last >= idle:
            break
    return bytes(buf)


def set_brightness(ser, pct, template, auto=False, verbose=False):
    """Send one brightness frame. Returns the applied percent, or None if the card
    did not acknowledge."""
    payload = build_brightness_payload(template, pct=pct, auto=auto)
    frame = build_frame(payload)
    ser.reset_input_buffer()
    ser.write(frame)
    ser.flush()
    rx = read_reply(ser)
    acked = any(fp[0] == 0x01 for fp, _ok in deframe(rx))
    if verbose:
        print(f"  sent {len(frame)} B, got {len(rx)} B back, ACK={acked}")
    if not acked:
        return None
    # Report the level actually encoded (clamped int), not the caller's float.
    return payload[PCT_OFFS[0]] if pct is not None else None


def set_auto(ser, enabled, template, pct=None, verbose=False):
    """Enable/disable the card's own ambient loop. `pct` None leaves the level
    bytes at whatever the template holds (HDset keeps the current level when it
    flips the flag); pass a percent to set both in one frame."""
    payload = build_brightness_payload(template, pct=pct, auto=enabled)
    ser.reset_input_buffer()
    ser.write(build_frame(payload))
    ser.flush()
    rx = read_reply(ser)
    acked = any(fp[0] == 0x01 for fp, _ok in deframe(rx))
    if verbose:
        print(f"  auto={enabled}: got {len(rx)} B back, ACK={acked}")
    return acked


def is_brightness_block(p):
    """True if `p` carries the sending-card block's brightness signature: 0xff at
    57 then four identical (percent, percent*128//100) pairs."""
    if len(p) != FRAME_LEN or p[57] != 0xFF:
        return False
    pcts = [p[o] for o in PCT_OFFS]
    if len(set(pcts)) != 1 or not 0 <= pcts[0] <= 100:
        return False
    return all(p[o] == pct_to_scaled(pcts[0]) for o in SCALED_OFFS)


def acquire_template(ser, out=None):
    """Read this wall's sending-card block straight off the hardware and return it
    as a class-0x02 write payload - the capture-free way to get a template.

    Dormant: TEMPLATE_QUERY is None because no such read query exists (see the
    note there), so this returns None without sending anything. Use
    --from-config instead. Kept in case a future firmware exposes one. Any block
    it did read is validated with
    is_brightness_block() before being trusted, so a wrong query cannot silently
    produce a garbage template."""
    if TEMPLATE_QUERY is None:
        return None
    sub, target = TEMPLATE_QUERY
    payload = bytes([0x01, sub, 0x00, target, 0x01, 0, 0, 0, 0x10]) + b"\x00" * 16
    ser.reset_input_buffer()
    ser.write(build_frame(payload))
    ser.flush()
    for p, _ok in deframe(read_reply(ser)):
        if is_brightness_block(p):
            tpl = bytearray(p)
            tpl[0], tpl[1], tpl[3] = BRIGHT_CLASS, BRIGHT_SUB, 0x00
            tpl = bytes(tpl)
            if out:
                with open(out, "wb") as f:
                    f.write(tpl)
            return tpl
    return None


def is_auto_block(p):
    """True if `p` is a multifunction auto-range block: class 0x02 / sub 0x01 /
    target 0x78, 521 bytes, declaring 512 data bytes, with a plausible
    (min <= max) percent pair at 457/458."""
    if len(p) != FRAME_LEN or p[0] != BRIGHT_CLASS or p[1] != AUTO_SUB:
        return False
    if p[3] != AUTO_TARGET or int.from_bytes(p[7:9], "big") != FRAME_LEN - HEADER_LEN_:
        return False
    lo, hi = p[AUTO_MIN_OFF], p[AUTO_MAX_OFF]
    return 0 <= lo <= hi <= 100


def load_auto_template(path=DEFAULT_AUTO_TEMPLATE):
    """This wall's captured class-0x02/sub-0x01 block (521 bytes)."""
    with open(path, "rb") as f:
        p = f.read()
    if not is_auto_block(p):
        raise ValueError(
            f"{path}: not a Huidu auto-range block (want {FRAME_LEN}B, class "
            f"0x{BRIGHT_CLASS:02x}/sub 0x{AUTO_SUB:02x}/target 0x{AUTO_TARGET:02x}); "
            f"got {len(p)}B class 0x{p[0]:02x}/sub 0x{p[1]:02x}/target 0x{p[3]:02x}")
    return p


def build_auto_payload(template, min_pct=None, max_pct=None):
    """Patch the auto min/max percents into a multifunction template. Either may
    be None to leave it unchanged. min is clamped below max."""
    p = bytearray(template)
    lo = p[AUTO_MIN_OFF] if min_pct is None else max(0, min(100, int(round(min_pct))))
    hi = p[AUTO_MAX_OFF] if max_pct is None else max(0, min(100, int(round(max_pct))))
    if lo > hi:
        lo, hi = hi, lo
    p[AUTO_MIN_OFF], p[AUTO_MAX_OFF] = lo, hi
    return bytes(p)


def set_auto_range(ser, min_pct, max_pct, template, verbose=False):
    """Set the HD-Y1's ambient min/max clamp. Returns (min, max) applied, or None.

    This steers a wall whose ambient loop runs ON THE CARD: with auto enabled the
    card ignores the manual level bytes, so min/max is the only way to influence
    its brightness. Enable the loop itself with set_auto()."""
    payload = build_auto_payload(template, min_pct, max_pct)
    ser.reset_input_buffer()
    ser.write(build_frame(payload))
    ser.flush()
    rx = read_reply(ser)
    acked = any(fp[0] == 0x01 for fp, _ok in deframe(rx))
    if verbose:
        print(f"  auto-range: got {len(rx)} B back, ACK={acked}")
    if not acked:
        return None
    return (payload[AUTO_MIN_OFF], payload[AUTO_MAX_OFF])


def read_auto_output(ser):
    """Poll an HD-Y1 for its LIVE auto brightness. Returns (output_pct, light) from
    the class-0x03 reply (offset 18 = current output %, offset 15 = light), or None
    if the card did not answer. Read-only (sends only the class-0x01 query), so it
    is safe to call every control tick to report what the on-card loop is doing."""
    ser.reset_input_buffer()
    ser.write(build_frame(AUTO_READ_QUERY))
    ser.flush()
    for p, _ok in deframe(read_reply(ser)):
        if len(p) == 521 and p[0] == 0x03:
            out = p[AUTO_OUTPUT_OFF]
            return (out if 0 <= out <= 100 else None, p[AUTO_LIGHT_OFF])
    return None


def extract_auto_template(pcap, out=DEFAULT_AUTO_TEMPLATE):
    """Pull the multifunction auto-range block out of a capture of HDset's
    auto-brightness screen.

    Rarely needed: the block is GENERIC across walls (verified on two), so
    default_auto.bin ships with the client and covers normal use. This exists for
    producing a specific wall's own block - the block is absent from HDset's saved
    config, so a capture is the only way to get one."""
    import hd_bright_analyze as H
    hs = [p for d, p in H.frames_for(pcap)
          if d == "H>D" and p[0] == BRIGHT_CLASS and p[1] == AUTO_SUB]
    if not hs:
        sys.exit(f"no class-0x{BRIGHT_CLASS:02x}/sub-0x{AUTO_SUB:02x} frame in {pcap}\n"
                 f"  capture HDset changing auto min/max on the multifunction card.")
    with open(out, "wb") as f:
        f.write(hs[0])
    print(f"wrote {out}: {len(hs[0])} bytes "
          f"(auto min {hs[0][AUTO_MIN_OFF]}%, max {hs[0][AUTO_MAX_OFF]}%)")
    return hs[0]


def fingerprint_path(template_path):
    """Where the wall fingerprint for a template lives."""
    return template_path + ".wall.json"


def probe_fingerprint(ser, max_cards=64, gap=3):
    """Identify the wall on the other end of `ser` by probing its receiving cards:
    [{index, width, height}, ...]. Read-only.

    Walks the chain until `gap` CONSECUTIVE indices do not answer, capped at
    `max_cards` - it must not stop at a fixed count. This used to probe only 4
    indices, which both truncated the record and weakened the guard: any two walls
    whose first four cards matched produced the same fingerprint, so a template
    could pass the check on the wrong wall. A present card answers a probe with a
    class-0x03 config block; an absent index replies with the ACK alone."""
    from hd_probe import build_frame as _bf, make_probe_payload, parse_config
    cards, misses = [], 0
    for idx in range(max_cards):
        ser.reset_input_buffer()
        ser.write(_bf(make_probe_payload(idx, sub=1)))
        ser.flush()
        found = None
        for p, _ok in deframe(read_reply(ser)):
            if p and p[0] == 0x03:
                found = parse_config(p)
                break
        if found is None:
            misses += 1
            if misses >= gap:
                break                      # end of the chain
            continue
        misses = 0
        cards.append({"index": found["index"], "width": found["width"],
                      "height": found["height"]})
    return sorted(cards, key=lambda c: (c["index"] is None, c["index"]))


def save_fingerprint(ser, template_path, max_cards=64, gap=3):
    """Record which wall a template belongs to, at commissioning time."""
    import json
    fp = probe_fingerprint(ser, max_cards, gap)
    with open(fingerprint_path(template_path), "w", encoding="utf-8") as f:
        json.dump({"cards": fp}, f, indent=2)
    return fp


def check_fingerprint(ser, template_path, max_cards=64, gap=3):
    """(ok, expected, actual) - does the connected wall match the one this
    template came from?

    Templates are wall-specific: comparing two walls' blocks showed 7 bytes of
    per-wall display geometry outside the brightness field, so sending the wrong
    wall's template would rewrite that wall's screen configuration. `ok` is True
    when no fingerprint has been recorded (nothing to check against)."""
    import json
    try:
        with open(fingerprint_path(template_path), encoding="utf-8") as f:
            expected = json.load(f).get("cards")
    except (OSError, ValueError):
        return True, None, None          # not recorded - cannot verify
    actual = probe_fingerprint(ser, max_cards, gap)
    return actual == expected, expected, actual


def extract_template_from_config(path, out=DEFAULT_TEMPLATE):
    """Pull this wall's template out of HDset's saved config - no capture, no
    sniffer, no USB at all.

    Accepts any HDset config that carries the block. Two known layouts:
      * newer HDset: `public/recvfile/net_default_new.xml`, two base64 layers down
        (net_default_new.xml -> SendCardPage -> SendCardBasicBin/Card0 data area);
      * a **screen-config export** - `.sss` on newer HDset, `.ssx` on older - both
        verified to yield a valid 521-byte template. The .ssx is the only file that holds
        the block on OLD HDset e.g. v2.1.3.46, where net_default.xml is just the box
        config): the block is a base64'd 55..d5-framed class-0x02 frame, and
        scan_file finds it by its EDID/brightness signature regardless of wrapper.
    Verified against a captured frame from the same wall (identical at all 521
    bytes but offset 22, the auto flag) and against a real .ssx export.

    This is THE provisioning path for a fleet - `extract_template` (from a pcap)
    is only needed where no config file holds the block."""
    from find_config import scan_file          # imported here: find_config
    good, _raw = scan_file(path)               # imports this module
    if not good:
        sys.exit(
            f"no sending-card block found INSIDE {path}\n"
            f"  (the file WAS read - it simply does not contain the block; this is\n"
            f"   NOT a filename check). The block often only lands in HDset's\n"
            f"   net_default_new.xml AFTER you Send the Sending-Card Parameters in\n"
            f"   HDset (changing brightness alone does not write it). Options:\n"
            f"   - point --config at net_default_new.xml, or at the HDset folder to\n"
            f"     auto-scan (find_config.py --scan <dir>);\n"
            f"   - or use the capture route:  provision_wall.py --capture <pcap>")
    payload = good[0][3]
    with open(out, "wb") as f:
        f.write(payload)
    print(f"wrote {out}: {len(payload)} bytes "
          f"(level {payload[PCT_OFFS[0]]}%, auto={payload[AUTO_OFF]})")
    return payload


def extract_template(pcap, out=DEFAULT_TEMPLATE):
    """Pull the class-0x02 payload out of a capture (needs tshark)."""
    import hd_bright_analyze as H
    hs = [p for d, p in H.frames_for(pcap)
          if d == "H>D" and p[0] == BRIGHT_CLASS and p[1] == BRIGHT_SUB]
    if not hs:
        sys.exit(f"no class-0x{BRIGHT_CLASS:02x} host->card frame in {pcap} "
                 f"(run hd_bright_analyze.py --check on it)")
    with open(out, "wb") as f:
        f.write(hs[0])
    print(f"wrote {out}: {len(hs[0])} bytes "
          f"(level {hs[0][PCT_OFFS[0]]}%, auto={hs[0][AUTO_OFF]})")
    return hs[0]


def main():
    ap = argparse.ArgumentParser(description="Set Huidu LED brightness")
    default_port = "COM10" if sys.platform == "win32" else "/dev/ttyUSB0"
    ap.add_argument("--port", default=default_port)
    ap.add_argument("--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("--template", default=DEFAULT_TEMPLATE,
                    help="class-0x02 frame captured from THIS wall")
    ap.add_argument("--set", type=float, metavar="PCT",
                    help="brightness percent 0-100 (also disables auto)")
    ap.add_argument("--auto", action="store_true",
                    help="hand brightness back to the card's hardware ambient loop")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the frame that would be sent, send nothing")
    ap.add_argument("--extract-template", metavar="PCAP",
                    help="rebuild the template from a capture and exit")
    ap.add_argument("--from-config", metavar="CFG",
                    help="build the template from HDset's saved config - a .sss/.ssx "
                         "screen-config export (works on old + new HDset) or "
                         "net_default_new.xml - no capture needed")
    ap.add_argument("--auto-template", default=DEFAULT_AUTO_TEMPLATE,
                    help="this wall's multifunction (auto-range) block")
    ap.add_argument("--auto-min", type=float, default=None,
                    help="HD-Y1 ambient: minimum brightness %% the card may use")
    ap.add_argument("--auto-max", type=float, default=None,
                    help="HD-Y1 ambient: maximum brightness %% the card may use")
    ap.add_argument("--extract-auto-template", metavar="PCAP",
                    help="rebuild the auto-range template from a capture of HDset's "
                         "auto-brightness screen (not in HDset's config) and exit")
    ap.add_argument("--save-fingerprint", action="store_true",
                    help="probe this wall and record which wall the template "
                         "belongs to (do this at commissioning)")
    args = ap.parse_args()

    if args.from_config:
        extract_template_from_config(args.from_config, args.template)
        print("  next: run --save-fingerprint on that wall so the template "
              "cannot later be used on the wrong one.")
        return 0
    if args.extract_auto_template:
        extract_auto_template(args.extract_auto_template, args.auto_template)
        return 0
    if args.extract_template:
        extract_template(args.extract_template, args.template)
        print("  next: run --save-fingerprint on that wall so the template "
              "cannot later be used on the wrong one.")
        return 0
    want_range = args.auto_min is not None or args.auto_max is not None
    if (args.set is None and not args.auto and not args.save_fingerprint
            and not want_range):
        ap.error("give --set PCT, --auto, --auto-min/--auto-max, or --save-fingerprint")

    # --auto-min/--auto-max write the multifunction block and never touch the
    # brightness template, so do not demand one for that path.
    template = None
    if not want_range:
        try:
            template = load_template(args.template)
        except (OSError, ValueError) as e:
            sys.exit(f"template: {e}\n  Capture one from THIS wall, then: "
                     f"hd_bright.py --extract-template set_100.pcapng")

    if want_range and args.dry_run:
        try:
            atpl = load_auto_template(args.auto_template)
        except (OSError, ValueError) as e:
            sys.exit(f"auto template: {e}\n  build one with: "
                     f"hd_bright.py --extract-auto-template <capture>.pcapng")
        p = build_auto_payload(atpl, args.auto_min, args.auto_max)
        print(f"== dry run: class=0x{p[0]:02x} sub=0x{p[1]:02x} target=0x{p[3]:02x} "
              f"{len(p)} B payload ==")
        print(f"  auto min [{AUTO_MIN_OFF}] = {p[AUTO_MIN_OFF]}%")
        print(f"  auto max [{AUTO_MAX_OFF}] = {p[AUTO_MAX_OFF]}%")
        return 0

    if args.dry_run:
        payload = build_brightness_payload(
            template, pct=args.set, auto=True if args.auto else False)
        print(f"== dry run: class=0x{payload[0]:02x} sub=0x{payload[1]:02x} "
              f"{len(payload)} B payload ==")
        print(f"  auto flag  [22] = {payload[AUTO_OFF]}")
        print(f"  level      {list(PCT_OFFS)} = {[payload[o] for o in PCT_OFFS]}")
        print(f"  scaled     {list(SCALED_OFFS)} = {[payload[o] for o in SCALED_OFFS]}")
        print(f"  full frame = {len(build_frame(payload))} B (preamble+payload+CRC)")
        return 0

    try:
        ser = open_serial(args.port, args.baud)
    except Exception as e:
        sys.exit(f"Cannot open {args.port}: {e}\n"
                 f"  HDset holds the port - close it first.")
    try:
        if args.save_fingerprint:
            fp = save_fingerprint(ser, args.template)
            if not fp:
                print("== no receiving cards answered - fingerprint NOT saved ==")
                return 1
            print(f"== fingerprint saved -> {fingerprint_path(args.template)} ==")
            for c in fp:
                print(f"   card {c['index']}: {c['width']}x{c['height']}")
            return 0
        if want_range:
            try:
                atpl = load_auto_template(args.auto_template)
            except (OSError, ValueError) as e:
                sys.exit(f"auto template: {e}\n  build one with: "
                         f"hd_bright.py --extract-auto-template <capture>.pcapng")
            res = set_auto_range(ser, args.auto_min, args.auto_max, atpl, verbose=True)
            if res is None:
                print("== no ACK from the card - auto range NOT set ==")
                return 1
            print(f"== HD-Y1 ambient range -> min {res[0]}%  max {res[1]}% ==")
            print("   the card clamps its own ambient loop to this range;")
            print("   enable the loop itself with --auto")
            return 0
        if args.auto:
            ok = set_auto(ser, True, template, pct=args.set, verbose=True)
            lvl = (f", level -> {int(round(args.set))}%" if args.set is not None
                   else f" (level left at the template's {template[PCT_OFFS[0]]}%)")
            print(f"== auto-brightness ENABLED (hardware ambient loop){lvl} - "
                  f"{'ACK' if ok else 'NO ACK'} ==")
            print("   the card now drives brightness from its light sensor, "
                  "clamped to its configured min/max.")
            print("   revert with:  hd_bright.py --set <pct>   (turns auto off)")
            return 0 if ok else 1
        applied = set_brightness(ser, args.set, template, auto=False, verbose=True)
        if applied is None:
            print("== no ACK from the card - check the cable/port and retry ==")
            return 1
        print(f"== brightness -> {applied}% "
              f"(scaled {pct_to_scaled(applied)}/128), auto disabled ==")
        return 0
    finally:
        ser.close()


if __name__ == "__main__":
    sys.exit(main())
