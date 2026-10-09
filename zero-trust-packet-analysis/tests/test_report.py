import subprocess
import sys
from pathlib import Path

import pytest
from scapy.all import wrpcap

from zt import synth
from zt.report import analyze, render_html, tenet_scorecard


@pytest.fixture()
def pcap(tmp_path):
    pk = [synth.tcp("192.168.1.2", "1.1.1.1", 50000, 443, synth.client_hello()),
          synth.tcp("1.1.1.1", "192.168.1.2", 443, 50000, synth.server_hello(0x0304)),
          synth.tcp("192.168.1.2", "127.0.0.1", 50001, 80, b"GET / HTTP/1.1\r\n\r\n"),
          synth.udp("192.168.1.2", "8.8.8.8", 5000, 53)]
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pk)
    return path


def test_analyze_reads_pcap(pcap):
    d = analyze(pcap)
    assert (d["total_packets"], d["trusted"], d["not_trusted"]) == (4, 2, 1)


def test_scorecard_flags_encrypt_everything(pcap):
    card = {t: s for t, s, _ in tenet_scorecard(analyze(pcap))}
    assert card["Encrypt Everything"] == "VIOLATED"
    assert card["Verify Explicitly"] == "UPHELD"
    assert card["Assume Breach"] == "UPHELD"
    assert card["Least Privilege"] == "MANUAL REVIEW"


def test_html_is_self_contained(pcap):
    html = render_html(analyze(pcap), "t.pcap")
    assert html.count("data:image/png;base64,") == 4
    assert "http://" not in html.replace("http://www.w3.org", "")   # no external assets


def test_cli_writes_report(pcap, tmp_path):
    out = tmp_path / "r.html"
    subprocess.run([sys.executable, "-m", "zt.report", str(pcap), "-o", str(out)], check=True, capture_output=True)
    assert out.exists() and "Zero Trust Indicator Report" in out.read_text(encoding="utf-8")


def test_committed_sample_reproduces_report_numbers():
    sample = Path(__file__).resolve().parents[1] / "samples" / "synthetic_lab_capture.pcap"
    d = analyze(sample)
    assert (d["total_packets"], d["trusted"], d["not_trusted"]) == (1268, 241, 20)
    assert (d["trusted_pct"], d["not_trusted_pct"]) == (92.3, 7.7)
