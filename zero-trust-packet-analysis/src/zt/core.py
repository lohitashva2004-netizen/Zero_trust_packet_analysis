"""Shared classification engine used by BOTH the offline report and the live tracker.

Port tables, thresholds and the classify() rule are carried over unchanged from
the original live_zero_trust_tracker.py so the two tools always agree.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import Counter, defaultdict
from typing import Optional

from scapy.all import IP, IPv6, TCP

from .tls import parse_tls_hello

PLAINTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 69: "TFTP", 143: "IMAP", 110: "POP3"}
LATERAL_MOVEMENT_PORTS = {445: "SMB", 135: "MS-RPC", 3389: "RDP"}
ENCRYPTED_PORTS = {443, 993, 995, 22, 465, 636}
FANOUT_THRESHOLD = 8      # distinct private peers before a host is flagged
MAX_EVENTS = 50           # flagged events kept for the live feed


def is_private(ip: str) -> bool:
    """RFC 1918 IPv4 (10/8, 172.16/12, 192.168/16) or IPv6 unique-local (fc00::/7)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 4:
        a, b = addr.packed[0], addr.packed[1]
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    return addr.packed[0] & 0xFE == 0xFC


def classify(sport: int, dport: int, plaintext_ports: Optional[dict] = None) -> tuple[str, Optional[str]]:
    """Port-based verdict for one TCP segment: (label, reason).

    ``plaintext_ports`` lets a caller extend the built-in table, e.g. {8080: "HTTP-alt"}.
    """
    plaintext = PLAINTEXT_PORTS if plaintext_ports is None else plaintext_ports
    for p in (sport, dport):
        if p in plaintext:
            return "not_trusted", f"Plaintext ({plaintext[p]}) on port {p}"
        if p in LATERAL_MOVEMENT_PORTS:
            return "not_trusted", f"Lateral-movement risk ({LATERAL_MOVEMENT_PORTS[p]}) on port {p}"
    for p in (sport, dport):
        if p in ENCRYPTED_PORTS:
            return "trusted", f"Encrypted traffic on port {p}"
    return "unclassified", None


def parse_port_args(items) -> dict:
    """['8080:HTTP-alt', '8000'] -> {8080: 'HTTP-alt', 8000: 'custom'}"""
    out = {}
    for item in items or []:
        port, _, name = item.partition(":")
        out[int(port)] = name or "custom"
    return out


class TrafficStats:
    """Thread-safe running statistics fed one packet at a time."""

    def __init__(self, include_ipv6: bool = False, fanout_threshold: int = FANOUT_THRESHOLD,
                 extra_plaintext_ports: Optional[dict] = None):
        self.include_ipv6 = include_ipv6
        self.plaintext_ports = {**PLAINTEXT_PORTS, **(extra_plaintext_ports or {})}
        self.fanout_threshold = fanout_threshold
        self._lock = threading.Lock()
        self.total_packets = 0
        self.tcp_packets = 0
        self.counts = {"trusted": 0, "not_trusted": 0, "unclassified": 0}
        self.plaintext_hits: Counter = Counter()
        self.lateral_hits: Counter = Counter()
        self.peers: dict[str, set] = defaultdict(set)
        self.tls_negotiated: Counter = Counter()
        self.tls_offered: Counter = Counter()
        self.recent_events: list[dict] = []
        self.start_time = time.time()

    # ------------------------------------------------------------------ input
    def _endpoints(self, pkt):
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        if self.include_ipv6 and IPv6 in pkt:
            return pkt[IPv6].src, pkt[IPv6].dst
        return None

    def _event(self, ts, src, dst, detail):
        self.recent_events.insert(0, {"time": time.strftime("%H:%M:%S", time.localtime(ts)),
                                      "src": src, "dst": dst, "detail": detail})
        del self.recent_events[MAX_EVENTS:]

    def process(self, pkt, ts: Optional[float] = None) -> None:
        ends = self._endpoints(pkt)
        if ends is None:
            return
        src, dst = ends
        ts = float(ts if ts is not None else getattr(pkt, "time", time.time()))
        with self._lock:
            self.total_packets += 1
            if is_private(src) and is_private(dst):
                self.peers[src].add(dst)
            if TCP not in pkt:
                return
            self.tcp_packets += 1
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            label, detail = classify(sport, dport, self.plaintext_ports)
            self.counts[label] += 1
            for table, hits in ((self.plaintext_ports, self.plaintext_hits), (LATERAL_MOVEMENT_PORTS, self.lateral_hits)):
                for p in (sport, dport):
                    if p in table:
                        hits[p] += 1
            if label == "not_trusted" and detail:
                self._event(ts, src, dst, detail)
            hello = parse_tls_hello(bytes(pkt[TCP].payload))
            if hello:
                bucket = self.tls_negotiated if hello["msg"] == "ServerHello" else self.tls_offered
                bucket[hello["name"]] += 1
                if hello["deprecated"] and hello["msg"] == "ServerHello":
                    self._event(ts, src, dst, f"Deprecated {hello['name']} negotiated (ServerHello)")

    # ----------------------------------------------------------------- output
    def snapshot(self) -> dict:
        with self._lock:
            classified = sum(self.counts.values())
            pct = lambda n: round(100.0 * n / classified, 1) if classified else 0.0
            return {
                "total_packets": self.total_packets,
                "tcp_packets": self.tcp_packets,
                "trusted": self.counts["trusted"],
                "not_trusted": self.counts["not_trusted"],
                "unclassified": self.counts["unclassified"],
                "trusted_pct": pct(self.counts["trusted"]),
                "not_trusted_pct": pct(self.counts["not_trusted"]),
                "plaintext_hits": [{"port": p, "protocol": self.plaintext_ports[p], "packets": n}
                                   for p, n in self.plaintext_hits.most_common()],
                "lateral_hits": [{"port": p, "protocol": LATERAL_MOVEMENT_PORTS[p], "packets": n}
                                 for p, n in self.lateral_hits.most_common()],
                "fanout": sorted(({"host": h, "peers": len(s)} for h, s in self.peers.items()
                                  if len(s) >= self.fanout_threshold), key=lambda x: -x["peers"]),
                "tls_negotiated": dict(self.tls_negotiated),
                "tls_offered": dict(self.tls_offered),
                "recent_events": list(self.recent_events),
                "elapsed_s": int(time.time() - self.start_time),
                "fanout_threshold": self.fanout_threshold,
            }
