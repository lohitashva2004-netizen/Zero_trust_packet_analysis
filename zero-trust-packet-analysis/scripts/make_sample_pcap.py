"""Create samples/synthetic_lab_capture.pcap.

SYNTHETIC. It is built so that running the analyzer reproduces the headline
numbers of the project report (1268 IP packets, 241 Trusted, 20 Not Trusted,
all of the latter plaintext HTTP on port 80, plus one deprecated TLS 1.0
ServerHello). It is NOT the original capture (which contains real browsing
traffic and is not published).
"""

import random
from pathlib import Path

from scapy.all import wrpcap

from zt import synth

OUT = Path(__file__).resolve().parents[1] / "samples" / "synthetic_lab_capture.pcap"


def main() -> None:
    rnd = random.Random(2026)
    me, web, lab = "192.168.1.20", "142.250.77.46", "127.0.0.1"
    pkts = []

    # --- Trusted: 241 TCP segments on encrypted ports (HTTPS) ---------------
    pkts.append(synth.tcp(me, web, 50001, 443, synth.client_hello(0x0303, (0x0304, 0x0303))))
    pkts.append(synth.tcp(web, me, 443, 50001, synth.server_hello(0x0304)))
    pkts.append(synth.tcp(me, web, 50002, 443, synth.client_hello(0x0303, (0x0303,))))
    pkts.append(synth.tcp(web, me, 443, 50002, synth.server_hello(0x0303)))
    pkts.append(synth.tcp(web, "203.0.113.9", 443, 50003, synth.server_hello(0x0301)))   # deprecated TLS 1.0
    while len(pkts) < 241:
        a, b = (me, web) if rnd.random() < 0.5 else (web, me)
        pkts.append(synth.tcp(a, b, 50001 + len(pkts) % 7, 443, bytes(rnd.getrandbits(8) for _ in range(40))))

    # --- Not Trusted: 20 plaintext HTTP segments on port 80 -----------------
    for i in range(10):
        pkts.append(synth.tcp(me, lab, 51000 + i, 80, b"GET / HTTP/1.1\r\nHost: lab\r\n\r\n"))
        pkts.append(synth.tcp(lab, me, 80, 51000 + i, b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"))

    # --- Non-TCP background (DNS / QUIC-like UDP) to reach 1268 IP packets --
    while len(pkts) < 1268:
        pkts.append(synth.udp(me, "8.8.8.8", 40000 + len(pkts) % 50, rnd.choice([53, 443])))

    rnd.shuffle(pkts)
    OUT.parent.mkdir(exist_ok=True)
    wrpcap(str(OUT), pkts)
    print(f"wrote {len(pkts)} packets -> {OUT}")


if __name__ == "__main__":
    main()
