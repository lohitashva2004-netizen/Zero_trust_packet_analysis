import pytest
from zt import TrafficStats
from zt.synth import client_hello, server_hello, tcp
from zt.tls import parse_tls_hello


def test_server_hello_tls12():
    r = parse_tls_hello(server_hello(0x0303))
    assert (r["msg"], r["name"], r["deprecated"]) == ("ServerHello", "TLS 1.2", False)


def test_server_hello_tls13_uses_supported_versions_extension():
    # legacy field says 1.2; the real version lives in the extension
    assert parse_tls_hello(server_hello(0x0304))["name"] == "TLS 1.3"


def test_server_hello_tls10_is_deprecated():
    r = parse_tls_hello(server_hello(0x0301))
    assert r["name"] == "TLS 1.0" and r["deprecated"] is True


def test_client_hello_reports_highest_offered_version():
    assert parse_tls_hello(client_hello(0x0303, (0x0304, 0x0303)))["name"] == "TLS 1.3"
    assert parse_tls_hello(client_hello(0x0303, (0x0303,)))["name"] == "TLS 1.2"


def test_grease_values_are_ignored():
    assert parse_tls_hello(client_hello(0x0303, (0x0A0A, 0x0304, 0x0303)))["name"] == "TLS 1.3"


def test_record_layer_version_alone_is_not_mistaken_for_tls10():
    # client_hello() puts 0x0301 in the record header, as real clients do
    assert parse_tls_hello(client_hello(0x0303, (0x0303,)))["deprecated"] is False


@pytest.mark.parametrize("junk", [b"", b"GET / HTTP/1.1\r\n", b"\x16\x03\x01", b"\x17\x03\x03" + b"x" * 60, b"\x16\x03\x01\x00" + b"\xff" * 50])
def test_non_hello_or_truncated_payloads_return_none(junk):
    assert parse_tls_hello(junk) is None


def test_deprecated_serverhello_raises_an_event_and_is_counted():
    s = TrafficStats()
    s.process(tcp("203.0.113.9", "192.168.1.2", 443, 50000, server_hello(0x0301)))
    d = s.snapshot()
    assert d["tls_negotiated"] == {"TLS 1.0": 1}
    assert "Deprecated TLS 1.0" in d["recent_events"][0]["detail"]
