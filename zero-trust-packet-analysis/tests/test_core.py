import pytest
from zt import TrafficStats, classify, is_private
from zt.synth import tcp, udp


@pytest.mark.parametrize("ip,expected", [
    ("10.1.2.3", True), ("172.16.0.1", True), ("172.31.255.1", True), ("172.32.0.1", False),
    ("192.168.1.20", True), ("192.169.1.1", False), ("8.8.8.8", False),
    ("127.0.0.1", False), ("fd12::1", True), ("2401:4900::1", False), ("not-an-ip", False),
])
def test_is_private(ip, expected):
    assert is_private(ip) is expected


@pytest.mark.parametrize("sport,dport,label", [
    (50000, 443, "trusted"), (22, 50000, "trusted"), (993, 50000, "trusted"),
    (50000, 80, "not_trusted"), (23, 50000, "not_trusted"), (50000, 21, "not_trusted"),
    (50000, 445, "not_trusted"), (3389, 50000, "not_trusted"), (50000, 135, "not_trusted"),
    (50000, 8080, "unclassified"),
])
def test_classify(sport, dport, label):
    assert classify(sport, dport)[0] == label


def test_plaintext_beats_encrypted_when_both_present():
    assert classify(443, 80)[0] == "not_trusted"


def test_reason_names_protocol_and_port():
    assert classify(50000, 23)[1] == "Plaintext (Telnet) on port 23"
    assert classify(50000, 445)[1] == "Lateral-movement risk (SMB) on port 445"


def test_stats_counts_and_percentages():
    s = TrafficStats()
    for _ in range(9):
        s.process(tcp("192.168.1.2", "1.1.1.1", 50000, 443))
    s.process(tcp("192.168.1.2", "1.1.1.1", 50000, 80))
    s.process(udp("192.168.1.2", "8.8.8.8", 4000, 53))
    d = s.snapshot()
    assert (d["total_packets"], d["tcp_packets"]) == (11, 10)
    assert (d["trusted"], d["not_trusted"], d["unclassified"]) == (9, 1, 0)
    assert d["trusted_pct"] == 90.0 and d["not_trusted_pct"] == 10.0
    assert d["plaintext_hits"] == [{"port": 80, "protocol": "HTTP", "packets": 1}]
    assert d["recent_events"][0]["detail"] == "Plaintext (HTTP) on port 80"


def test_lateral_hits_recorded():
    s = TrafficStats()
    s.process(tcp("10.0.0.5", "10.0.0.9", 50000, 445))
    assert s.snapshot()["lateral_hits"][0]["protocol"] == "SMB"


def test_fanout_flags_host_at_threshold():
    s = TrafficStats(fanout_threshold=8)
    for i in range(8):
        s.process(tcp("10.0.0.1", f"10.0.1.{i + 1}", 50000, 8080))
    assert s.snapshot()["fanout"] == [{"host": "10.0.0.1", "peers": 8}]


def test_fanout_ignores_public_peers():
    s = TrafficStats(fanout_threshold=3)
    for i in range(10):
        s.process(tcp("10.0.0.1", f"8.8.8.{i + 1}", 50000, 443))
    assert s.snapshot()["fanout"] == []


def test_event_feed_is_capped_and_newest_first():
    s = TrafficStats()
    for i in range(80):
        s.process(tcp("192.168.1.2", "1.1.1.1", 50000, 80))
    assert len(s.snapshot()["recent_events"]) == 50


def test_empty_snapshot_has_no_division_by_zero():
    d = TrafficStats().snapshot()
    assert d["trusted_pct"] == 0.0 and d["total_packets"] == 0


def test_extra_plaintext_port_is_opt_in():
    from zt.core import parse_port_args
    assert classify(50000, 8080)[0] == "unclassified"            # default table: 8080 is not flagged
    assert classify(50000, 8080, {8080: "HTTP-alt"}) == ("not_trusted", "Plaintext (HTTP-alt) on port 8080")
    s = TrafficStats(extra_plaintext_ports=parse_port_args(["8080:HTTP-alt"]))
    s.process(tcp("192.168.1.2", "127.0.0.1", 50000, 8080))
    assert s.snapshot()["plaintext_hits"] == [{"port": 8080, "protocol": "HTTP-alt", "packets": 1}]
