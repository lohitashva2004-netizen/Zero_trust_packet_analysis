"""Live Zero Trust tracker: sniff an interface and serve an auto-refreshing dashboard.

Live capture needs elevated privileges:
    Windows : run the terminal "as Administrator" (Npcap must be installed)
    Linux/macOS : sudo

    python -m zt.live                       # default interface
    python -m zt.live --iface "Wi-Fi"       # Windows interface name as shown in Wireshark
    python -m zt.live --iface eth0 --port 8500
    python -m zt.live --demo                # no capture: feed it synthetic traffic
"""

from __future__ import annotations

import argparse
import json
import random
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from scapy.all import sniff

from .core import TrafficStats, parse_port_args

DASHBOARD_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Live Zero Trust Traffic Tracker</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#21262d;--txt:#e6edf3;--mut:#8b949e;--g:#2ecc71;--r:#ef4444}
body{margin:0;background:var(--bg);color:var(--txt);font-family:Segoe UI,Arial,sans-serif}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 28px;background:var(--card);border-bottom:1px solid var(--line)}
header h1{font-size:15px;margin:0}#stat{font-size:12px;color:var(--g)}main{max-width:900px;margin:18px auto;padding:0 16px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.card b{font-size:26px;display:block}.card span{font-size:10px;color:var(--mut);letter-spacing:1px}.panel{margin-top:12px}.panel h3{font-size:12px;margin:0 0 10px}
.bar{height:14px;border-radius:7px;background:var(--r);overflow:hidden}.bar i{display:block;height:100%;background:var(--g);transition:width .6s}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}table{width:100%;border-collapse:collapse;font-size:12px}
th{color:var(--mut);text-align:left;font-size:10px;letter-spacing:1px;padding:4px}td{padding:4px;border-top:1px solid var(--line)}
.none{color:var(--mut);font-style:italic}#feed{font-family:Consolas,monospace;font-size:12px;max-height:220px;overflow:auto}
</style></head><body>
<header><h1>Live Zero Trust Traffic Tracker</h1><div id="stat">&#9679; connecting&hellip;</div></header><main>
<div class="cards"><div class="card"><b id="total">0</b><span>TOTAL PACKETS</span></div>
<div class="card"><b id="trusted" style="color:var(--g)">0</b><span>TRUSTED</span></div>
<div class="card"><b id="nt" style="color:var(--r)">0</b><span>NOT TRUSTED</span></div>
<div class="card"><b id="unc" style="color:var(--mut)">0</b><span>UNCLASSIFIED</span></div></div>
<div class="panel"><h3>Trust ratio (live)</h3><div class="bar"><i id="ratio" style="width:100%"></i></div></div>
<div class="two"><div class="panel"><h3>Plaintext protocol hits</h3><div id="plain"></div></div>
<div class="panel"><h3>Lateral-movement port hits</h3><div id="lat"></div></div></div>
<div class="panel"><h3 id="fanh">Fan-out hosts (segmentation risk)</h3><div id="fan"></div></div>
<div class="panel"><h3>Live flagged event feed</h3><div id="feed" class="none">Waiting for flagged traffic&hellip;</div></div></main>
<script>
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const tbl=(h,rows)=>rows.length?'<table><tr>'+h.map(x=>'<th>'+x+'</th>').join('')+'</tr>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+esc(c)+'</td>').join('')+'</tr>').join('')+'</table>':'<span class="none">None detected yet</span>';
async function tick(){try{const d=await (await fetch('/data')).json();
total.textContent=d.total_packets;trusted.textContent=d.trusted;nt.textContent=d.not_trusted;unc.textContent=d.unclassified;
const c=d.trusted+d.not_trusted;ratio.style.width=(c?100*d.trusted/c:100)+'%';
plain.innerHTML=tbl(['PORT','PACKETS'],d.plaintext_hits.map(h=>[h.port+' '+h.protocol,h.packets]));
lat.innerHTML=tbl(['PORT','PACKETS'],d.lateral_hits.map(h=>[h.port+' '+h.protocol,h.packets]));
fanh.textContent='Fan-out hosts (segmentation risk, '+d.fanout_threshold+'+ peers)';
fan.innerHTML=tbl(['HOST','DISTINCT INTERNAL PEERS'],d.fanout.map(h=>[h.host,h.peers]));
feed.className=d.recent_events.length?'':'none';
feed.innerHTML=d.recent_events.length?d.recent_events.map(e=>'<div>'+esc(e.time)+'  '+esc(e.src)+' &rarr; '+esc(e.dst)+'  '+esc(e.detail)+'</div>').join(''):'Waiting for flagged traffic...';
stat.textContent='\\u25CF Connection ok | '+d.elapsed_s+'s elapsed';stat.style.color='var(--g)';
}catch(e){stat.textContent='\\u25CF Connection lost';stat.style.color='var(--r)';}}
tick();setInterval(tick,1500);
</script></body></html>"""


def make_handler(stats: TrafficStats):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # silence default request logging

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body, ctype = DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8"
            elif self.path == "/data":
                body, ctype = json.dumps(stats.snapshot()).encode("utf-8"), "application/json"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


def _demo_feeder(stats: TrafficStats) -> None:
    from . import synth
    rnd = random.Random()
    me, web, lab = "192.168.1.20", "142.250.77.46", "127.0.0.1"
    while True:
        r = rnd.random()
        if r < 0.80:
            stats.process(synth.tcp(me, web, 50000, 443, b"\x17\x03\x03" + b"x" * 30))
        elif r < 0.90:
            stats.process(synth.tcp(me, lab, 51000, 80, b"GET / HTTP/1.1\r\n\r\n"))
        else:
            stats.process(synth.udp(me, "8.8.8.8", 40000, 53))
        time.sleep(0.15)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Live Zero Trust traffic tracker dashboard")
    ap.add_argument("--iface", default=None,
                    help='Network interface to sniff on (default: scapy auto-selects). On Windows use the name shown in Wireshark, e.g. "Wi-Fi".')
    ap.add_argument("--port", type=int, default=8642, help="Local dashboard port (default: 8642)")
    ap.add_argument("--no-open", action="store_true", help="Don't auto-open the browser")
    ap.add_argument("--include-ipv6", action="store_true", help="Also analyse IPv6 packets (default: IPv4 only)")
    ap.add_argument("--plaintext-port", action="append", default=[], metavar="PORT[:NAME]",
                    help="treat an extra port as plaintext, e.g. 8080:HTTP-alt (repeatable)")
    ap.add_argument("--demo", action="store_true", help="Feed synthetic traffic instead of sniffing (no privileges needed)")
    args = ap.parse_args(argv)

    stats = TrafficStats(include_ipv6=args.include_ipv6, extra_plaintext_ports=parse_port_args(args.plaintext_port))
    server = HTTPServer(("localhost", args.port), make_handler(stats))
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = f"http://localhost:{args.port}/"
    print(f"Live dashboard running at {url}")
    print("Press Ctrl+C to stop capturing.\n")
    if not args.no_open:
        webbrowser.open(url)

    try:
        if args.demo:
            _demo_feeder(stats)
        else:
            sniff(iface=args.iface, prn=stats.process, store=False)
    except PermissionError:
        print("\nPermission denied: live capture needs elevated privileges.")
        print("Windows: close this terminal and reopen Command Prompt/PowerShell")
        print('by right-clicking it and choosing "Run as administrator", then rerun this script.')
        print("macOS/Linux: rerun with sudo.")
    except KeyboardInterrupt:
        print("\nStopped capturing. Final snapshot:")
        print(json.dumps(stats.snapshot(), indent=2))


if __name__ == "__main__":
    main()
