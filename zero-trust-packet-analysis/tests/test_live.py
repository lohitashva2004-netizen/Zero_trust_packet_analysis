import json
import threading
import urllib.request
from http.server import HTTPServer

from zt import TrafficStats
from zt.live import make_handler
from zt.synth import tcp


def test_dashboard_serves_html_and_json():
    stats = TrafficStats()
    stats.process(tcp("192.168.1.2", "127.0.0.1", 50000, 80))
    server = HTTPServer(("127.0.0.1", 0), make_handler(stats))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        assert b"Live Zero Trust Traffic Tracker" in urllib.request.urlopen(base + "/").read()
        data = json.loads(urllib.request.urlopen(base + "/data").read())
        assert data["not_trusted"] == 1 and data["plaintext_hits"][0]["port"] == 80
        try:
            urllib.request.urlopen(base + "/nope")
            assert False, "expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        server.shutdown()
