#!/usr/bin/env python3
"""hd_bright_analyze.py - find the Huidu brightness command by diffing HDset
captures taken at known brightness levels (or from one 'move-the-slider'
capture). Huidu analog of ../nova_probe_re/bright_analyze.py.

We already know Huidu framing (hd_probe.py / PROTOCOL.md):

    55 55 55 55 55 55 55 D5 | payload | CRC32(payload) little-endian
    payload[0] = command class, [1] = sub-command, [2] = receiving-card index

The probe uses class 0x01. Brightness is a different class/sub whose data byte
tracks the level. Capture HDset setting brightness to a few KNOWN levels and this
finds the byte + its offset automatically, in both directions.

Handles both capture formats, auto-detected:
  * USBPcap / usbmon  (Wireshark's usb.* fields)   <- recommended, software-only
  * ataradov usb-sniffer (usbll link-layer)         <- what we used for NovaStar
Requires tshark on PATH.

Name files with the level (e.g. set_100.pcapng, set_50.pcapng, set_20.pcapng), or
pass file:level explicitly.

    python hd_bright_analyze.py --check cap.pcapng        # capture health
    python hd_bright_analyze.py --dump  cap.pcapng        # decode every frame
    python hd_bright_analyze.py --writes slide.pcapng     # list H>D cmds in order
    python hd_bright_analyze.py set_100.pcapng set_50.pcapng set_20.pcapng
    python hd_bright_analyze.py a.pcapng:100 b.pcapng:50  # explicit file:level
    python hd_bright_analyze.py                           # globs ./set_*.pcap*
"""
import glob
import os
import re
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

# Huidu framing, inlined from hd_probe.py so this analyzer needs only tshark +
# stdlib (no pyserial) - it runs wherever you keep the captures.
PREAMBLE = bytes.fromhex("55555555555555d5")


def crc32le(payload):
    return (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little")


def deframe(stream):
    """Yield (payload, True) for each CRC-valid Huidu frame in a byte stream.
    Frames have no length field: for each preamble, take the longest prefix up to
    the next preamble whose trailing 4 bytes are a valid CRC32 of the payload."""
    starts, i = [], 0
    while True:
        j = stream.find(PREAMBLE, i)
        if j < 0:
            break
        starts.append(j)
        i = j + 1
    starts.append(len(stream))
    frames = []
    for k in range(len(starts) - 1):
        bc = stream[starts[k] + len(PREAMBLE):starts[k + 1]]
        for end in range(len(bc), 4, -1):
            payload, crc = bc[:end - 4], bc[end - 4:end]
            if crc32le(payload) == crc:
                frames.append((payload, True))
                break
    return frames

# usbll PIDs (ataradov path)
PID_OUT, PID_IN, PID_SETUP = 0xE1, 0x69, 0x2D
PID_DATA0, PID_DATA1 = 0xC3, 0x4B
PID_ACK, PID_NAK, PID_STALL = 0xD2, 0x5A, 0x5E
TOKEN_PIDS = (PID_OUT, PID_IN, PID_SETUP)
DATA_PIDS = (PID_DATA0, PID_DATA1)
HANDSHAKE_PIDS = (PID_ACK, PID_NAK, PID_STALL)

# Huidu payload header: class, sub, idx, ..., 2-byte BIG-endian data length.
HEADER_LEN = 9
LEN_OFF = 7

# Capture-health counters, filled as a side effect of the (expensive) extraction
# pass so --check never has to walk a multi-GB pcap twice. pcap path -> dict.
_STATS = {}


# --------------------------------------------------------------------------- #
# tshark helpers
# --------------------------------------------------------------------------- #
def _tshark(pcap, args):
    # Guard first: a missing/unreadable path otherwise yields an empty tshark
    # result, which every downstream count reads as "0 frames" and reports as a
    # capture problem. Fail loudly instead - a typo must not look like a dud.
    if not os.path.isfile(pcap):
        sys.exit(f"no such capture file: {pcap}")
    try:
        return subprocess.run(["tshark", "-r", pcap] + args,
                              capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("tshark not found on PATH - install Wireshark/tshark.")


def _count(pcap, dfilter):
    r = _tshark(pcap, ["-Y", dfilter, "-T", "fields", "-e", "frame.number"])
    return sum(1 for ln in r.stdout.splitlines() if ln.strip())


def _hexbytes(s):
    s = s.strip().replace(":", "").replace(",", "").replace(" ", "")
    if not s or s == "<none>":
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def _int(s, default=None):
    s = (s or "").strip()
    if not s:
        return default
    try:
        return int(s, 0)
    except ValueError:
        try:
            return int(s)
        except ValueError:
            return default


def detect_format(pcap):
    if _count(pcap, "usbll") > 0:
        return "usbll"
    return "usb"


def _capinfos(pcap):
    """(duration_seconds, packet_count), or (None, None) if capinfos is absent.
    -M keeps the numbers exact instead of abbreviating them to '1,934 k'."""
    try:
        r = subprocess.run(["capinfos", "-M", "-u", "-c", pcap],
                           capture_output=True, text=True)
    except FileNotFoundError:
        return None, None
    dur = pkts = None
    for ln in r.stdout.splitlines():
        low = ln.lower()
        if low.startswith("capture duration"):
            m = re.search(r"([\d.]+)", ln)
            dur = float(m.group(1)) if m else None
        elif low.startswith("number of packets"):
            m = re.search(r"(\d+)", ln)
            pkts = int(m.group(1)) if m else None
    return dur, pkts


# --------------------------------------------------------------------------- #
# USBPcap / usbmon extraction (usb.* fields)
# --------------------------------------------------------------------------- #
def _read_usb(pcap):
    r = _tshark(pcap, ["-Y", "usb.transfer_type==0x03 && usb.capdata",
                       "-T", "fields", "-e", "frame.number",
                       "-e", "usb.device_address", "-e", "usb.endpoint_address",
                       "-e", "usb.capdata"])
    out = []
    for ln in r.stdout.splitlines():
        f = ln.split("\t")
        if len(f) < 4:
            f += [""] * (4 - len(f))
        frame, dev, ep, data = f
        raw = _hexbytes(data)
        if not raw:
            continue
        ep_i = _int(ep, 0)
        out.append((_int(frame, 0), _int(dev), ep_i,
                    "D>H" if (ep_i & 0x80) else "H>D", raw))
    return out


def _bursts_usb(pcap):
    pkts = _read_usb(pcap)
    # Bulk writes host->card. The tshark filter already restricts to bulk
    # transfers carrying data, so every H>D packet here is a real write.
    _STATS[pcap] = {"bulk_out": sum(1 for p in pkts if p[3] == "H>D"),
                    "bulk_in": sum(1 for p in pkts if p[3] == "D>H")}
    if not pkts:
        return []
    # pick the USB device whose stream carries the Huidu preamble (in case the
    # capture spans a whole hub); fall back to all if none matches.
    by_dev = {}
    for _, dev, _, _, raw in pkts:
        by_dev.setdefault(dev, bytearray()).extend(raw)
    led_dev = next((d for d, buf in by_dev.items() if PREAMBLE in bytes(buf)), None)

    bursts, cur_dir, cur, cur_frame = [], None, bytearray(), None
    for frame, dev, _, dirn, raw in pkts:
        if led_dev is not None and dev != led_dev:
            continue
        if dirn != cur_dir:
            if cur:
                bursts.append((cur_frame, cur_dir, bytes(cur)))
            cur, cur_dir, cur_frame = bytearray(), dirn, frame
        cur += raw
    if cur:
        bursts.append((cur_frame, cur_dir, bytes(cur)))
    return [b for b in bursts if len(b[2]) >= 2]


# --------------------------------------------------------------------------- #
# ataradov usbll extraction (link-layer)
# --------------------------------------------------------------------------- #
def _read_usbll(pcap):
    r = _tshark(pcap, ["-Y", "usbll.pid==0xe1 || usbll.pid==0x69 || "
                       "usbll.pid==0x2d || usbll.pid==0xc3 || usbll.pid==0x4b || "
                       "usbll.pid==0xd2 || usbll.pid==0x5a || usbll.pid==0x5e",
                       "-T", "fields", "-e", "frame.number", "-e", "usbll.pid",
                       "-e", "usbll.device_addr", "-e", "usbll.endp",
                       "-e", "usbll.data"])
    for ln in r.stdout.splitlines():
        f = ln.split("\t")
        if len(f) < 5:
            f += [""] * (5 - len(f))
        frame, pid, addr, endp, data = f
        pid_i = _int(pid)
        if pid_i is None:
            continue
        yield (_int(frame, 0), pid_i, _int(addr), _int(endp), data)


def _detect_bulk_pipe_ll(events):
    counts = {}
    for _, pid, addr, endp, _ in events:
        if pid in (PID_IN, PID_OUT) and endp not in (None, 0) and addr is not None:
            counts[(addr, endp)] = counts.get((addr, endp), 0) + 1
    if not counts:
        return None, None
    return max(counts, key=counts.get)


def _bursts_usbll(pcap):
    events = list(_read_usbll(pcap))
    dev, ep = _detect_bulk_pipe_ll(events)
    # A write to the card is an OUT token on a NON-ZERO endpoint; endpoint 0 is
    # the control pipe, which only ever carries CP210x status polling. This is
    # the single number that distinguishes "HDset never sent anything" from a
    # genuine decode failure.
    _STATS[pcap] = {
        "bulk_out": sum(1 for _f, pid, _a, endp, _d in events
                        if pid == PID_OUT and endp not in (None, 0)),
        "bulk_in": sum(1 for _f, pid, _a, endp, _d in events
                       if pid == PID_IN and endp not in (None, 0)),
        "pipe": (dev, ep),
    }
    bursts, cur_dir, cur, cur_frame = [], None, bytearray(), None
    tok_addr = tok_endp = tok_dir = None
    pending = None
    for frame, pid, addr, endp, data in events:
        if pid in TOKEN_PIDS:
            tok_addr, tok_endp = addr, endp
            tok_dir = "D>H" if pid == PID_IN else "H>D"
            pending = None
            continue
        if pid in DATA_PIDS:
            if tok_addr != dev or tok_endp != ep:
                pending = None
                continue
            # Hold the packet until its handshake: the card NAKs bulk writes
            # while its buffer is full and the host RETRANSMITS the identical
            # packet. Concatenating those duplicates corrupts the byte stream
            # and every CRC then fails, so only ACKed data may be appended.
            pending = (tok_dir, frame, _hexbytes(data))
            continue
        if pid in HANDSHAKE_PIDS:
            if pending is None:
                continue
            dirn, dframe, raw = pending
            pending = None
            if pid != PID_ACK:
                continue                      # NAK/STALL -> host will resend
            if dirn != cur_dir:
                if cur:
                    bursts.append((cur_frame, cur_dir, bytes(cur)))
                cur, cur_dir, cur_frame = bytearray(), dirn, dframe
            cur += raw
    if cur:
        bursts.append((cur_frame, cur_dir, bytes(cur)))
    return [b for b in bursts if len(b[2]) >= 2]


# --------------------------------------------------------------------------- #
# frames
# --------------------------------------------------------------------------- #
def bursts(pcap):
    return _bursts_usbll(pcap) if detect_format(pcap) == "usbll" else _bursts_usb(pcap)


def frames_for(pcap):
    """[(dir, payload_bytes), ...] for every CRC-valid Huidu frame."""
    out = []
    for _frame, dirn, burst in bursts(pcap):
        for payload, _ok in deframe(burst):
            out.append((dirn, payload))
    return out


def _cls_sub_idx(p):
    return (p[0] if len(p) > 0 else None,
            p[1] if len(p) > 1 else None,
            p[2] if len(p) > 2 else None)


def declared_len(p):
    """(data_length, ok) from the big-endian uint16 at payload[7:9].

    Payload is a 9-byte header followed by `data_length` bytes, so a well-formed
    frame satisfies 9 + data_length == len(payload). Verified on every known
    frame: the 25-byte probe frames declare 16, the 521-byte config frame
    declares 512. `ok` is a cheap structural check that a frame from an
    unknown class is real and not a chance CRC match."""
    if len(p) < HEADER_LEN:
        return None, False
    n = int.from_bytes(p[LEN_OFF:LEN_OFF + 2], "big")
    return n, (HEADER_LEN + n == len(p))


def selector(dirn, p):
    """Route key for grouping: direction + class + sub + payload length."""
    cls, sub, _ = _cls_sub_idx(p)
    return (dirn, cls, sub, len(p))


def level_from_name(name):
    m = re.search(r"(\d+)", os.path.basename(name))
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------- #
# modes
# --------------------------------------------------------------------------- #
# A dud ataradov capture is dominated by syslog "USB PHY error" noise. A healthy
# capture carries only a handful of syslog frames, so the threshold is generous.
DUD_SYSLOG_MIN = 100


def check(pcap):
    """Triage a capture into one of the distinct failure modes, so a bad capture
    is caught while the rig is still up rather than during analysis."""
    fmt = detect_format(pcap)
    fs = frames_for(pcap)                     # also fills _STATS[pcap]
    st = _STATS.get(pcap, {})
    bulk_out, bulk_in = st.get("bulk_out"), st.get("bulk_in")
    hd = sum(1 for d, _ in fs if d == "H>D")
    dh = len(fs) - hd
    dur, npkts = _capinfos(pcap)

    print(f"== {os.path.basename(pcap)} health ==")
    print(f"  format detected : {fmt}  (usb=USBPcap/usbmon, usbll=ataradov)")
    if dur is not None:
        extra = f"   ({npkts:,} packets)" if npkts else ""
        print(f"  capture duration: {dur:.1f}s{extra}")
    if fmt == "usbll":
        print(f"  usbll pkts      : {_count(pcap, 'usbll')}")
    else:
        print(f"  usb bulk w/data : {_count(pcap, 'usb.transfer_type==0x03 && usb.capdata')}")
    print(f"  bulk OUT/IN     : {bulk_out} write(s) host->card, {bulk_in} read(s)")
    print(f"  CRC-valid frames: {len(fs)}   (H>D {hd}, D>H {dh})")

    if hd > 0:
        print("  -> GOOD: host->card commands are present. Run --writes on a")
        print("     slider capture, or pass several set_<level>.pcap files to")
        print("     correlate the brightness byte.")
        return True

    # No host->card command decoded. One extra pass to say WHICH failure it is.
    syslog_n = _count(pcap, "syslog")
    if syslog_n >= DUD_SYSLOG_MIN:
        print(f"  -> BAD (dud sniffer): {syslog_n} syslog/PHY-error frames.")
        print("     The CP210x is FULL-SPEED (12 Mbps) - re-arm the sniffer at")
        print("     Full Speed and capture again. Nothing here is decodable.")
    elif bulk_out == 0:
        print("  -> BAD (nothing was sent): the capture is healthy and covers the")
        print("     right device, but the host never wrote a single byte to the")
        print("     card. In HDset the brightness slider only STAGES the value -")
        print("     you must press the Send button, with the sniffer running, and")
        print("     see the wall actually change.")
    else:
        print(f"  -> BAD (extraction): {bulk_out} write(s) reached the card but no")
        print("     host->card frame decoded. Framing/pipe-detection problem, not a")
        print("     capture problem - the capture itself is fine. Run --dump.")
    return False


def dump(pcap):
    fs = frames_for(pcap)
    print(f"== {os.path.basename(pcap)}: {len(fs)} CRC-valid frame(s) ==")
    print("  dir  class sub  idx  len  datalen ok  payload")
    for d, p in fs:
        cls, sub, idx = _cls_sub_idx(p)
        n, ok = declared_len(p)
        pp = p.hex() if len(p) <= 32 else p[:32].hex() + f"..(+{len(p)-32}B)"
        print(f"  {d}  {_h(cls)}   {_h(sub)}  {_h(idx)}  {len(p):3d}  "
              f"{'--' if n is None else n:>7}  {'y' if ok else 'N':<2}  {pp}")


def _varying_offsets(payloads):
    """offset -> [values...] for byte offsets that are NOT constant across a set
    of equal-ish-length payloads."""
    if not payloads:
        return {}
    n = min(len(p) for p in payloads)
    out = {}
    for off in range(n):
        vals = [p[off] for p in payloads]
        if len(set(vals)) > 1:
            out[off] = vals
    return out


def writes(pcap):
    """List host->device frames in order (a slider capture). Then flag the byte
    offsets that vary within the dominant class/sub group - the value byte."""
    hs = [p for d, p in frames_for(pcap) if d == "H>D"]
    print(f"== {os.path.basename(pcap)}: {len(hs)} host->device frame(s) ==")
    if not hs:
        print("  none — was HDset actively sending (slider moved) during capture?")
        return
    for p in hs:
        cls, sub, idx = _cls_sub_idx(p)
        pp = p.hex() if len(p) <= 40 else p[:40].hex() + f"..(+{len(p)-40}B)"
        print(f"  class={_h(cls)} sub={_h(sub)} idx={_h(idx)} len={len(p):3d}  {pp}")

    # group by (class, sub, len); the biggest group is the repeated command
    groups = {}
    for p in hs:
        groups.setdefault(selector("H>D", p), []).append(p)
    key = max(groups, key=lambda k: len(groups[k]))
    grp = groups[key]
    print(f"\n  dominant command: class={_h(key[1])} sub={_h(key[2])} len={key[3]} "
          f"({len(grp)} frames)")
    varie = _varying_offsets(grp)
    if not varie:
        print("  no byte varied within it — capture more distinct slider positions.")
        return
    for off, vals in sorted(varie.items()):
        uniq = []
        for v in vals:
            if not uniq or uniq[-1] != v:
                uniq.append(v)
        seq = " ".join(f"{v}" for v in uniq[:24]) + (" ..." if len(uniq) > 24 else "")
        print(f"    payload offset {off:3d} varies:  {seq}")
    print("  -> the offset whose value marches with the slider is the brightness byte.")


def correlate(captures):
    """captures: {level: [(dir, payload), ...]}. Find a payload byte offset that
    tracks the level, per (dir, class, sub, len) group present in >=3 levels."""
    levels = sorted(captures)
    table = {}                       # (dir, selector) -> {level: payload}
    for lvl in levels:
        for d, p in captures[lvl]:
            table.setdefault((d, selector(d, p)), {}).setdefault(lvl, p)

    print(f"\n== correlating {len(table)} group(s) over levels {levels} ==")
    hits = []
    for key, per_lvl in table.items():
        seen = sorted(per_lvl)
        if len(seen) < 3:
            continue
        minlen = min(len(per_lvl[l]) for l in seen)
        for off in range(minlen):
            vals = [per_lvl[l][off] for l in seen]
            if len(set(vals)) < 2:
                continue
            if _monotonic(seen, vals):
                hits.append((key, off, list(zip(seen, vals))))

    if not hits:
        print("  no byte tracked the level. Check the captures differ, widen the")
        print("  level spread, or run --dump on one to eyeball the frames.")
        return
    for (d, sel), off, pairs in sorted(hits, key=lambda h: -_fit_quality(h[2])):
        _, cls, sub, ln = sel
        print(f"\n  [{d}] class={_h(cls)} sub={_h(sub)} len={ln}  -> payload byte offset {off}")
        for lvl, v in pairs:
            print(f"      level {lvl:3d}%  ->  byte 0x{v:02x} ({v:3d})   "
                  f"[{v}/255={round(v/255*100)}%]")
        print(f"      mapping guess: {_guess(pairs)}")


def _monotonic(levels, vals):
    inc = all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1))
    dec = all(vals[i] >= vals[i + 1] for i in range(len(vals) - 1))
    return inc or dec


def _fit_quality(pairs):
    ed = sum(abs(v - l) for l, v in pairs)
    e255 = sum(abs(v - round(l / 100 * 255)) for l, v in pairs)
    return -min(ed, e255)


def _guess(pairs):
    ed = sum(abs(v - l) for l, v in pairs)
    e255 = sum(abs(v - round(l / 100 * 255)) for l, v in pairs)
    if ed <= e255 and ed <= len(pairs):
        return "byte == level  (0-100 percent stored directly)"
    if e255 < ed and e255 <= len(pairs):
        return "byte == round(level/100 * 255)  (0-255 scale, 0xff = 100%)"
    return f"nonlinear/unknown (|err| direct={ed}, 0-255={e255})"


def _h(v):
    return "--" if v is None else f"{v:#04x}"


def parse_args(argv):
    items = []
    for a in argv:
        if ":" in a and not re.search(r"\.pcap", a.rsplit(":", 1)[1]):
            path, lvl = a.rsplit(":", 1)
            items.append((path, int(lvl)))
        else:
            lvl = level_from_name(a)
            if lvl is None:
                sys.exit(f"cannot read a level from '{a}' - use file:level")
            items.append((a, lvl))
    return items


def main():
    argv = sys.argv[1:]
    if argv and argv[0] in ("--check", "--dump", "--writes"):
        mode = {"--check": check, "--dump": dump, "--writes": writes}[argv[0]]
        rest = argv[1:] or sys.exit(f"{argv[0]} needs a pcap")
        for p in rest:
            mode(p)
        return
    items = parse_args(argv) if argv else [
        (p, level_from_name(p))
        for p in sorted(glob.glob(os.path.join(HERE, "set_*.pcap")) +
                        glob.glob(os.path.join(HERE, "set_*.pcapng")))]
    if not items:
        sys.exit(__doc__)
    captures = {}
    for pcap, lvl in items:
        fs = frames_for(pcap)
        print(f"-- {os.path.basename(pcap)}  (level {lvl}%): {len(fs)} frames")
        captures[lvl] = fs
    correlate(captures)


if __name__ == "__main__":
    main()
