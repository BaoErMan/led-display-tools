#!/usr/bin/env python3
"""
led_vendor.py - Identify a sending-card LED controller family (Huidu vs NovaStar)
from a single captured serial frame.

Both controllers ride an identical CP210x USB-UART bridge, so USB descriptors do
not distinguish them — you must look at the bulk-data framing:

    Huidu (HDset)     55 55 55 55 55 55 55 D5 | payload | CRC32(payload) LE
    NovaStar (NovaLCT) 55 AA (req) / AA 55 (rep) | … | (0x5555 + Σbytes[2:-2]) LE

The one-byte tell is frame[1]: 0x55 -> Huidu (mid-preamble), 0xAA -> NovaStar.
`identify()` additionally validates the trailer checksum for a definitive answer.

Shared by ../led_probe_re/hd_probe.py and ../nova_probe_re/nova_probe.py.
Run directly to classify a frame:  python led_vendor.py 55aa004a…a156
"""
import sys
import zlib

HUIDU_PREAMBLE = bytes.fromhex("55555555555555d5")
NOVA_MARKERS = (b"\x55\xaa", b"\xaa\x55")
NOVA_CKSUM_SEED = 0x5555


def huidu_crc32(payload: bytes) -> bytes:
    """Huidu trailer: zlib CRC32 of the payload, little-endian (4 bytes)."""
    return (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little")


def nova_cksum(frame_without_ck: bytes) -> bytes:
    """NovaStar trailer: (0x5555 + sum of bytes after the 2-byte start marker),
    little-endian (2 bytes). `frame_without_ck` runs from the start marker
    through the last data byte (i.e. the whole frame minus its 2 checksum bytes).
    """
    return ((NOVA_CKSUM_SEED + sum(frame_without_ck[2:])) & 0xFFFF).to_bytes(2, "little")


def vendor(frame: bytes) -> str:
    """Classify by header only: 'huidu', 'novastar', or 'unknown'."""
    if frame[:8] == HUIDU_PREAMBLE:
        return "huidu"
    if frame[:2] in NOVA_MARKERS:
        return "novastar"
    return "unknown"


def identify(frame: bytes):
    """Return (vendor, checksum_ok). The checksum check makes the result
    definitive even if a header pattern matched by chance."""
    v = vendor(frame)
    if v == "huidu":
        body = frame[len(HUIDU_PREAMBLE):]
        if len(body) >= 4:
            return v, huidu_crc32(body[:-4]) == body[-4:]
    elif v == "novastar":
        if len(frame) >= 4:
            return v, nova_cksum(frame[:-2]) == frame[-2:]
    return v, False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python led_vendor.py <frame-hex>")
    fr = bytes.fromhex(sys.argv[1].replace(" ", ""))
    v, ok = identify(fr)
    print(f"{v}  (checksum {'valid' if ok else 'INVALID/short'})")
