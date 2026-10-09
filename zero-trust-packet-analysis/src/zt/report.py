"""Offline analysis: read a .pcap/.pcapng, classify every packet, write a
single self-contained HTML report (charts embedded as base64 PNGs).

    python -m zt.report my_lab_capture.pcapng -o zero_trust_report.html
"""

from __future__ import annotations

import argparse
import base64
import html
import io
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scapy.all import PcapReader

from .core import TrafficStats, parse_port_args

GREEN, RED, GREY = "#4caf50", "#e53935", "#9e9e9e"


def analyze(path: str, include_ipv6: bool = False, extra_plaintext_ports: dict | None = None) -> dict:
    stats = TrafficStats(include_ipv6=include_ipv6, extra_plaintext_ports=extra_plaintext_ports)
    with PcapReader(str(path)) as reader:          # streams: large captures are fine
        for pkt in reader:
            stats.process(pkt)
    return stats.snapshot()


def tenet_scorecard(d: dict) -> list[tuple[str, str, str]]:
    """(tenet, status, evidence). Four tenets have packet-level indicators; Least
    Privilege depends on access-policy context a capture cannot show."""
    neg = d["tls_negotiated"]
    modern = neg.get("TLS 1.2", 0) + neg.get("TLS 1.3", 0)
    dep = sum(n for v, n in neg.items() if v in ("SSL 3.0", "TLS 1.0", "TLS 1.1"))
    plain = sum(h["packets"] for h in d["plaintext_hits"])
    lateral = sum(h["packets"] for h in d["lateral_hits"])
    rows = [
        ("Verify Explicitly", "UPHELD" if modern else "NO EVIDENCE",
         f"{modern} TLS 1.2/1.3 ServerHello(s) seen" if modern else "no TLS handshake seen in this capture"),
        ("Least Privilege", "MANUAL REVIEW", "needs access-policy context; not derivable from packets alone"),
        ("Assume Breach", "VIOLATED" if lateral else "UPHELD",
         f"{lateral} lateral-movement packets (SMB/RDP/MS-RPC)" if lateral else "no SMB, RDP or MS-RPC traffic"),
        ("Micro-segmentation", "VIOLATED" if d["fanout"] else "UPHELD",
         f"{len(d['fanout'])} host(s) reached >= {d['fanout_threshold']} internal peers" if d["fanout"]
         else f"no host reached {d['fanout_threshold']} internal peers"),
        ("Encrypt Everything", "VIOLATED" if (plain or dep) else "UPHELD",
         f"{plain} plaintext packets" + (f"; {dep} deprecated-TLS ServerHello(s)" if dep else "")),
    ]
    return rows


def _png(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    plt.close(fig)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def charts(d: dict) -> dict:
    out = {}
    vals = [d["trusted"], d["not_trusted"], d["unclassified"]]
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    if d["trusted"] + d["not_trusted"]:
        ax.pie([d["trusted"], d["not_trusted"]], labels=["Trusted", "Not Trusted"], colors=[GREEN, RED],
               autopct="%1.1f%%", startangle=90, counterclock=False, textprops={"fontsize": 9})
    ax.set_title("Trusted vs Not Trusted (share)", fontsize=10)
    out["pie"] = _png(fig)

    fig, ax = plt.subplots(figsize=(3.8, 3.2))
    ax.bar(["Trusted", "Not Trusted", "Unclassified"], vals, color=[GREEN, RED, GREY])
    ax.set_ylabel("Packet count"); ax.set_title("Trusted vs Not Trusted (count)", fontsize=10)
    out["bar"] = _png(fig)

    fig, ax = plt.subplots(figsize=(3.8, 3.0))
    hits = d["plaintext_hits"] + d["lateral_hits"]
    if hits:
        ax.bar([f"{h['port']}\n{h['protocol']}" for h in hits], [h["packets"] for h in hits], color=RED)
    else:
        ax.text(0.5, 0.5, "none detected", ha="center", transform=ax.transAxes)
    ax.set_ylabel("Packet count"); ax.set_title("Plaintext / lateral-movement hits", fontsize=10)
    out["hits"] = _png(fig)

    fig, ax = plt.subplots(figsize=(3.8, 3.0))
    if d["fanout"]:
        top = d["fanout"][:8]
        ax.barh([h["host"] for h in top][::-1], [h["peers"] for h in top][::-1], color="#ff9800")
        ax.set_xlabel("Distinct internal peers")
    else:
        ax.text(0.5, 0.5, "No fan-out / segmentation\nviolations detected", ha="center", transform=ax.transAxes, fontsize=9)
        ax.set_xticks([]); ax.set_yticks([])
    ax.set_title("Top hosts by fan-out", fontsize=10)
    out["fanout"] = _png(fig)
    return out


CSS = """body{font-family:Segoe UI,Arial,sans-serif;background:#f3f4f6;margin:0;color:#111}
header{background:#1a2332;color:#fff;padding:18px 32px}header h1{margin:0;font-size:20px}header p{margin:4px 0 0;font-size:12px;opacity:.7}
main{max-width:1000px;margin:20px auto;padding:0 16px}.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#fff;border-radius:8px;padding:14px 18px;flex:1;min-width:150px;box-shadow:0 1px 3px #0001}
.card b{font-size:24px;display:block}.card span{font-size:11px;color:#666}.g{color:#2e7d32}.r{color:#c62828}
section{background:#fff;border-radius:8px;padding:16px 20px;margin-top:14px;box-shadow:0 1px 3px #0001}
section h2{font-size:14px;margin:0 0 10px;border-bottom:1px solid #eee;padding-bottom:8px}
.row{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}.row img{max-width:48%;min-width:260px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}
th{background:#fafafa;font-size:11px;text-transform:uppercase;color:#666}.UPHELD{color:#2e7d32;font-weight:600}
.VIOLATED{color:#c62828;font-weight:600}.MANUAL,.NO{color:#e65100;font-weight:600}small{color:#777}"""


def _table(headers, rows):
    if not rows:
        return "<p><small>None detected.</small></p>"
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def render_html(d: dict, source: str) -> str:
    c = charts(d)
    score = "".join(f"<tr><td>{html.escape(t)}</td><td class='{s.split()[0]}'>{s}</td><td>{html.escape(e)}</td></tr>"
                    for t, s, e in tenet_scorecard(d))
    tls = _table(["Version", "Negotiated (ServerHello)", "Offered (ClientHello)"],
                 [(v, d["tls_negotiated"].get(v, 0), d["tls_offered"].get(v, 0))
                  for v in sorted(set(d["tls_negotiated"]) | set(d["tls_offered"]))])
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Zero Trust Indicator Report</title><style>{CSS}</style></head><body>
<header><h1>Zero Trust Indicator Report</h1><p>File: {html.escape(Path(source).name)} &nbsp;|&nbsp; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p></header><main>
<div class="cards">
<div class="card"><b>{d['total_packets']}</b><span>Total IP packets</span></div>
<div class="card"><b>{d['tcp_packets']}</b><span>TCP packets classified</span></div>
<div class="card"><b class="g">{d['trusted']} ({d['trusted_pct']}%)</b><span>Trusted</span></div>
<div class="card"><b class="r">{d['not_trusted']} ({d['not_trusted_pct']}%)</b><span>Not Trusted</span></div>
<div class="card"><b>{d['unclassified']}</b><span>Unclassified</span></div></div>
<p><small>Percentages are shares of classified TCP packets. Non-TCP packets (UDP, ICMP) count toward the IP total only.</small></p>
<section><h2>Trust overview</h2><div class="row"><img src="{c['pie']}"><img src="{c['bar']}"></div></section>
<section><h2>Encrypt Everything &mdash; plaintext protocol findings</h2>
{_table(['Port','Protocol','Packets'], [(h['port'], h['protocol'], h['packets']) for h in d['plaintext_hits']])}
<div class="row"><img src="{c['hits']}"></div></section>
<section><h2>Assume Breach &mdash; lateral-movement ports</h2>
{_table(['Port','Protocol','Packets'], [(h['port'], h['protocol'], h['packets']) for h in d['lateral_hits']])}</section>
<section><h2>Micro-segmentation &mdash; fan-out hosts (&ge; {d['fanout_threshold']} internal peers)</h2>
{_table(['Host','Distinct internal peers'], [(h['host'], h['peers']) for h in d['fanout']])}
<div class="row"><img src="{c['fanout']}"></div></section>
<section><h2>TLS versions seen in handshakes</h2>{tls}</section>
<section><h2>NIST SP 800-207 tenet scorecard</h2><table><tr><th>Tenet</th><th>Status</th><th>Evidence</th></tr>{score}</table>
<p><small>Automated indicators are candidates, not conclusions: confirm each in Wireshark with the matching display filter.</small></p></section>
</main></body></html>"""


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Zero Trust indicator report from a packet capture")
    ap.add_argument("pcap", help="path to a .pcap or .pcapng file")
    ap.add_argument("-o", "--output", default="zero_trust_report.html")
    ap.add_argument("--include-ipv6", action="store_true", help="also analyse IPv6 packets (default: IPv4 only)")
    ap.add_argument("--plaintext-port", action="append", default=[], metavar="PORT[:NAME]",
                    help="treat an extra port as plaintext, e.g. 8080:HTTP-alt (repeatable)")
    args = ap.parse_args(argv)
    d = analyze(args.pcap, args.include_ipv6, parse_port_args(args.plaintext_port))
    Path(args.output).write_text(render_html(d, args.pcap), encoding="utf-8")
    print(f"{d['total_packets']} IP packets | trusted {d['trusted']} ({d['trusted_pct']}%) | "
          f"not trusted {d['not_trusted']} ({d['not_trusted_pct']}%) | unclassified {d['unclassified']}")
    print(f"report written to {args.output}")


if __name__ == "__main__":
    main()
