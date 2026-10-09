# Findings

Results come from one live capture on a Wi-Fi interface plus the lab traffic described in the methodology. The original capture is not published because it contains real browsing traffic and IP addresses; `samples/synthetic_lab_capture.pcap` reproduces its headline numbers.

## Offline report

| Metric | Value |
|---|---|
| Total IP packets analysed | 1268 |
| Trusted | 241 (92.3%) |
| Not Trusted | 20 (7.7%) |
| Unclassified | 0 |
| Not Trusted breakdown | 20 plaintext HTTP packets, port 80 |

The percentages are shares of the **classified TCP** packets (241 + 20 = 261). The remaining ~1,000 IP packets are non-TCP (e.g. UDP) and only count toward the IP total.

![HTML report](images/fig06_html_report_summary.png)
![Charts](images/fig07_chart_breakdown.png)

## Live dashboard

![Live dashboard](images/fig09_live_dashboard.png)

A session of 812 packets showed 271 Trusted and none flagged: the live tracker agreed with the offline run that normal browsing was encrypted.

## Scorecard

| Tenet | Result | Evidence |
|---|---|---|
| Verify Explicitly | UPHELD | TLS 1.2 / 1.3 handshakes present on encrypted sessions |
| Least Privilege | UPHELD (manual) | No unexpected host-to-service traffic patterns observed |
| Assume Breach | UPHELD | No SMB, RDP or MS-RPC traffic |
| Micro-segmentation | UPHELD | No host exceeded the internal fan-out threshold |
| Encrypt Everything | **VIOLATED** | 20 plaintext HTTP packets on port 80; a deprecated TLS 1.0 handshake was also seen alongside TLS 1.2 traffic |

## Remediation

1. Migrate the affected service from HTTP to HTTPS (TLS 1.2 or higher).
2. Disable TLS 1.0 / 1.1 on all endpoints (both are deprecated by RFC 8996).
3. Introduce VLAN-based micro-segmentation policies before scaling beyond a lab.
