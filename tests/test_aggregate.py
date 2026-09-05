import numpy as np
import pandas as pd

from src.aggregate import aggregate_bins, protocol_mix
from src.mask import mask_ip

MY = "192.168.0.10"
SRV = "93.184.216.34"


def _pkt(t, src, dst, length=100, proto="TCP", stream=0, ack_rtt=None, retrans=False, dns_time=None, dns_resp=0):
    return {
        "t": t, "ip.src": src, "ip.dst": dst, "frame.len": length, "protocol": proto,
        "tcp.stream": stream, "ack_rtt": ack_rtt, "is_retrans": retrans, "is_fast_retrans": False,
        "is_spurious": False, "is_tcp": stream is not None, "dns_time": dns_time, "is_dns_resp": bool(dns_resp),
    }


def test_rtt_uses_only_incoming_acks_and_retrans_rate():
    rows = []
    # bin 0: 서버->나 ACK 5개 RTT 20ms, 내가 보낸 ACK(delayed ack 200ms) 5개는 무시돼야 함
    for i in range(5):
        rows.append(_pkt(i, SRV, MY, ack_rtt=0.020))
        rows.append(_pkt(i + 0.5, MY, SRV, ack_rtt=0.200))
    # bin 1: TCP 10개 중 재전송 2개 -> 20%
    for i in range(10):
        rows.append(_pkt(60 + i, SRV, MY, retrans=(i < 2)))
    # DNS 응답
    rows.append(_pkt(61, "8.8.8.8", MY, proto="DNS", stream=None, dns_time=0.030, dns_resp=1))
    df = pd.DataFrame(rows)
    bins = aggregate_bins(df, MY)
    assert len(bins) == 2
    assert abs(bins.loc[0, "rtt_mean"] - 20.0) < 1e-9
    assert bins.loc[0, "rtt_n"] == 5
    assert abs(bins.loc[1, "retrans_rate"] - 20.0) < 1e-9
    assert abs(bins.loc[1, "dns_mean"] - 30.0) < 1e-9
    assert np.isnan(bins.loc[1, "rtt_mean"])  # 표본 부족 -> NaN
    # 처리량: bin0 = 10 x 100B = 1000B x 8 / 60 s
    assert abs(bins.loc[0, "throughput_total"] - 1000 * 8 / 60 / 1e6) < 1e-12


def test_protocol_mix_groups():
    df = pd.DataFrame([
        _pkt(0, SRV, MY, 1000, "TLSv1.3"),
        _pkt(1, SRV, MY, 1000, "QUIC", stream=None),
        _pkt(2, SRV, MY, 500, "DNS", stream=None),
        _pkt(3, SRV, MY, 500, "ARP", stream=None),
    ])
    total, per_bin = protocol_mix(df)
    d = dict(zip(total["group"], total["bytes_pct"]))
    assert abs(d["TLS/HTTPS"] - 100 * 1000 / 3000) < 1e-9
    assert "Other" in d


def test_mask_ip():
    assert mask_ip("192.168.0.17") == "192.168.x.x"
    assert mask_ip("142.250.196.110") == "142.250.x.x"
    assert mask_ip(None) == "unknown"
    assert mask_ip("2001:db8::1").startswith("2001:0db8:")
