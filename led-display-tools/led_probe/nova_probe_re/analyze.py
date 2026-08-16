#!/usr/bin/env python3
"""analyze.py - decode the NovaStar frames in all_data.tsv.

Each row of all_data.tsv is a same-direction bulk *burst* (possibly several
USB transfers concatenated). A burst contains one logical NovaStar frame:

    [0:2]   start marker      55 AA = request (H>D),  AA 55 = response (D>H)
    [2]     ack/flag          00 request, echoes/!=00 on some replies
    [3]     serial number     increments per command, echoed in reply
    [4]     src address       FE = PC
    [5]     dst address
    [6]     device type
    [7]     port              sending-card output port
    [8:10]  board address     receiving-card index in the chain (LE)
    [10]    command           00 read, 01 write
    [11:15] register address  (LE)
    [15:17] data length       (BE)  <-- big-endian
    [17:17+len] data
    [last2] checksum
"""
import os

HERE = os.path.dirname(__file__)


def load():
    rows = []
    for line in open(os.path.join(HERE, "all_data.tsv")):
        frame, d, h = line.rstrip("\n").split("\t")
        rows.append((int(frame), d, bytes.fromhex(h)))
    return rows


HDR = 18           # bytes before the data payload
SEED = 0x5555      # NovaStar checksum seed


def checksum(frame_wo_ck):
    """frame_wo_ck = bytes from start marker through last data byte."""
    return (SEED + sum(frame_wo_ck[2:])) & 0xFFFF


def split_frames(burst):
    """Split a direction burst into checksum-validated frames. A burst may hold
    several frames (e.g. two requests when the card didn't answer the first)."""
    out = []
    b = burst
    while len(b) >= 20:
        if b[0:2] not in (b"\x55\xaa", b"\xaa\x55"):
            b = b[1:]
            continue
        dlen = int.from_bytes(b[16:18], "little")
        # candidate lengths: response/write carries dlen data; read request has none
        for flen in (HDR + dlen + 2, 20):
            if flen <= len(b) and checksum(b[:flen - 2]) == \
                    int.from_bytes(b[flen - 2:flen], "little"):
                out.append(b[:flen])
                b = b[flen:]
                break
        else:
            break          # no valid frame here
        nz = next((i for i, x in enumerate(b) if x != 0), len(b))
        b = b[nz:]         # skip zero padding between frames
    return out


# ---- checksum --------------------------------------------------------------
def sum16(b):
    return sum(b) & 0xFFFF


def crack_checksum(frames):
    cfgs = [("sum16 LE, body[2:-2]", "little", lambda b: b[2:-2]),
            ("sum16 BE, body[2:-2]", "big",    lambda b: b[2:-2]),
            ("sum16 LE, body[:-2]",  "little", lambda b: b[:-2]),
            ("sum16 BE, body[:-2]",  "big",    lambda b: b[:-2])]
    for name, end, body in cfgs:
        if all(sum16(body(b)) == int.from_bytes(b[-2:], end) for b in frames):
            return name
    return None


def show(frames):
    print("\n tag ser ak src dst dv pt addr  cm reg[11:16]  len  data")
    for d, b in frames:
        ack, ser, src, dst, dev, prt = b[2], b[3], b[4], b[5], b[6], b[7]
        addr = int.from_bytes(b[8:10], "little")
        cmd = b[10]
        reg = b[11:16].hex()
        dlen = int.from_bytes(b[16:18], "little")
        data = b[18:18 + dlen]
        cmds = "rd" if cmd == 0 else "wr"
        ascii_ = "".join(chr(x) if 32 <= x < 127 else "." for x in data)
        dd = data.hex()
        if len(dd) > 40:
            dd = dd[:40] + f"…(+{dlen-20}B)"
        tag = "REQ" if d == "H>D" else "rsp"
        print(f" {tag} {ser:3d} {ack:02x} {src:02x} {dst:02x} {dev:02x} {prt:02x} "
              f"{addr:04x} {cmds} {reg} {dlen:4d}  {dd}  |{ascii_[:24]}|")


if __name__ == "__main__":
    rows = load()
    frames = []
    leftover = 0
    for _, d, burst in rows:
        fs = split_frames(burst)
        frames += [(d, f) for f in fs]
        consumed = sum(len(f) for f in fs)
        leftover += max(0, len(burst) - consumed - 4)  # ignore tiny tails
    print(f"{len(frames)} checksum-valid frames from {len(rows)} bursts "
          f"({leftover} leftover bytes)")
    bad = [b for _, b in frames
           if checksum(b[:-2]) != int.from_bytes(b[-2:], "little")]
    print(f"checksum (0x5555 + sum(b[2:-2]), LE): {len(frames)-len(bad)}/{len(frames)} valid")
    show(frames)
