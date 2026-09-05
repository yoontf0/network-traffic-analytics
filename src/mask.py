"""IP 주소 마스킹. results/ 및 README 에 들어가는 모든 IP 는 이 함수를 거친다."""

from __future__ import annotations

import ipaddress


def mask_ip(ip: str | None) -> str:
    """사설 IP → 앞 2옥텟만, 공인 IP → 앞 2옥텟만 남기고 x.x 처리.

    >>> mask_ip("192.168.0.17")
    '192.168.x.x'
    >>> mask_ip("142.250.196.110")
    '142.250.x.x'
    """
    if not ip or not isinstance(ip, str):
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip.split(",")[0])
    except ValueError:
        return "unknown"
    if addr.version == 6:
        parts = addr.exploded.split(":")
        return ":".join(parts[:2]) + ":x:x:x:x:x:x"
    a, b, _, _ = str(addr).split(".")
    return f"{a}.{b}.x.x"
