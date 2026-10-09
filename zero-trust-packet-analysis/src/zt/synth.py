"""Builders for synthetic packets and TLS hellos.

Used by the unit tests and by scripts/make_sample_pcap.py so the project can be
demonstrated and tested without a live capture. Nothing here is real traffic.
"""

from __future__ import annotations

import struct

from scapy.all import IP, TCP, UDP, Ether, Raw

_RANDOM = bytes(range(32))


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _record(hs_type: int, body: bytes, record_version: int = 0x0301) -> bytes:
    hs = bytes([hs_type]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + struct.pack("!HH", record_version, len(hs)) + hs


def client_hello(legacy_version: int = 0x0303, offered=(0x0304, 0x0303)) -> bytes:
    exts = b""
    if offered:
        lst = b"".join(struct.pack("!H", v) for v in offered)
        exts = _ext(0x002B, bytes([len(lst)]) + lst)
    body = (struct.pack("!H", legacy_version) + _RANDOM + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    return _record(1, body)


def server_hello(negotiated: int = 0x0303) -> bytes:
    """TLS 1.3 servers still advertise 0x0303 in the legacy field and put the real
    version in supported_versions - exactly what the parser has to handle."""
    if negotiated == 0x0304:
        legacy, exts = 0x0303, _ext(0x002B, struct.pack("!H", 0x0304))
    else:
        legacy, exts = negotiated, b""
    body = (struct.pack("!H", legacy) + _RANDOM + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    return _record(2, body)


def tcp(src, dst, sport, dport, payload=b"", flags="PA"):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return pkt / Raw(payload) if payload else pkt


def udp(src, dst, sport, dport, payload=b"x" * 20):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)
