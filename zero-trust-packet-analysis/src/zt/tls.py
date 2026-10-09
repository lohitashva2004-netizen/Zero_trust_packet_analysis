"""Minimal TLS handshake sniffing from raw TCP payload bytes.

Looks only at the first record of a segment. A handshake split across several
TCP segments will not be parsed (see README limitations).
"""

from __future__ import annotations

from typing import Optional

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
DEPRECATED = {0x0300, 0x0301, 0x0302}   # RFC 8996 deprecates TLS 1.0 and 1.1
_EXT_SUPPORTED_VERSIONS = 0x002B


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def parse_tls_hello(payload: bytes) -> Optional[dict]:
    """Return {'msg', 'version', 'name', 'deprecated'} for a ClientHello / ServerHello.

    * ServerHello -> the version actually NEGOTIATED. For TLS 1.3 the legacy
      version field says 1.2, so the supported_versions extension is read.
    * ClientHello -> the highest version OFFERED.

    The record-layer version is deliberately ignored: nearly every modern client
    sends 0x0301 there for compatibility, so using it would mislabel TLS 1.2/1.3
    sessions as TLS 1.0.
    """
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        hs_type = payload[5]
        if hs_type not in (1, 2):
            return None
        version = _u16(payload, 9)
        i = 11 + 32                                   # skip the 32-byte random
        i += 1 + payload[i]                            # session id
        if hs_type == 1:                               # ClientHello
            i += 2 + _u16(payload, i)                  # cipher suites
            i += 1 + payload[i]                        # compression methods
        else:                                          # ServerHello
            i += 3                                     # cipher suite + compression
        best = version
        if i + 2 <= len(payload):
            ext_end = min(i + 2 + _u16(payload, i), len(payload))
            i += 2
            while i + 4 <= ext_end:
                ext_type, ext_len = _u16(payload, i), _u16(payload, i + 2)
                data = payload[i + 4:i + 4 + ext_len]
                if ext_type == _EXT_SUPPORTED_VERSIONS and data:
                    if hs_type == 2 and len(data) >= 2:
                        best = _u16(data, 0)
                    elif hs_type == 1:
                        offered = [_u16(data, k) for k in range(1, len(data) - 1, 2)]
                        known = [v for v in offered if v in TLS_VERSIONS]   # drops GREASE values
                        if known:
                            best = max(known)
                i += 4 + ext_len
        if best not in TLS_VERSIONS:
            return None
        return {
            "msg": "ClientHello" if hs_type == 1 else "ServerHello",
            "version": best,
            "name": TLS_VERSIONS[best],
            "deprecated": best in DEPRECATED,
        }
    except (IndexError, ValueError):
        return None
