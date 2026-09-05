"""패킷 단위 -> 1분 구간(bin) 품질 지표 집계.

지표 정의
- rtt_mean / rtt_max / rtt_p95 [ms]
    tcp.analysis.ack_rtt 중 **서버 -> 내 호스트 방향 ACK** 만 사용.
    (내 호스트가 보낸 ACK 의 ack_rtt 는 delayed-ACK 지연을 포함해 네트워크 RTT 가 아님)
- retrans_rate [%]
    (retransmission + fast_retransmission) / 전체 TCP 세그먼트 x 100
    spurious retransmission 은 별도 컬럼 (실제 손실 아님)
- dns_mean / dns_max [ms]
    dns.time (query -> response 시간), 응답 패킷 기준
- throughput_down / throughput_up / throughput_total [Mbps]
    frame.len 합 x 8 / BIN_SECONDS / 1e6
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .config import BIN_SECONDS, MIN_RTT_SAMPLES, PROTOCOL_GROUPS

COUNT_COLS = ["pkts", "tcp_pkts", "retrans_pkts", "spurious_pkts", "rtt_n", "dns_n"]


def _direction(df: pd.DataFrame, my_ip: str) -> pd.Series:
    d = pd.Series("other", index=df.index)
    d[df["ip.dst"] == my_ip] = "down"
    d[df["ip.src"] == my_ip] = "up"
    return d


def add_bins(df: pd.DataFrame, t0: float | None = None) -> pd.DataFrame:
    t0 = df["t"].min() if t0 is None else t0
    df = df.copy()
    df["bin"] = ((df["t"] - t0) // BIN_SECONDS).astype(int)
    df["t_rel_min"] = (df["t"] - t0) / 60.0
    return df


def aggregate_bins(df: pd.DataFrame, my_ip: str) -> pd.DataFrame:
    df = add_bins(df)
    df["dir"] = _direction(df, my_ip)

    tcp = df[df["is_tcp"]].copy()
    tcp["is_loss_retrans"] = tcp["is_retrans"] | tcp["is_fast_retrans"]

    # RTT: 내 호스트로 들어오는 ACK 에 찍힌 ack_rtt 만 (서버 왕복 시간)
    rtt = tcp[(tcp["dir"] == "down") & tcp["ack_rtt"].notna()]
    rtt_g = rtt.groupby("bin")["ack_rtt"]
    rtt_df = pd.DataFrame({
        "rtt_n": rtt_g.size(),
        "rtt_mean": rtt_g.mean() * 1000,
        "rtt_max": rtt_g.max() * 1000,
        "rtt_p95": rtt_g.quantile(0.95) * 1000,
    })

    tcp_g = tcp.groupby("bin")
    re_df = pd.DataFrame({
        "tcp_pkts": tcp_g.size(),
        "retrans_pkts": tcp_g["is_loss_retrans"].sum().astype(int),
        "spurious_pkts": tcp_g["is_spurious"].sum().astype(int),
    })
    re_df["retrans_rate"] = re_df["retrans_pkts"] / re_df["tcp_pkts"].replace(0, np.nan) * 100

    dns = df[df["is_dns_resp"] & df["dns_time"].notna()]
    dns_g = dns.groupby("bin")["dns_time"]
    dns_df = pd.DataFrame({
        "dns_n": dns_g.size(),
        "dns_mean": dns_g.mean() * 1000,
        "dns_max": dns_g.max() * 1000,
    })

    bytes_g = df.groupby(["bin", "dir"])["frame.len"].sum().unstack(fill_value=0)
    for c in ("down", "up"):
        if c not in bytes_g:
            bytes_g[c] = 0
    thr = pd.DataFrame({
        "pkts": df.groupby("bin").size(),
        "bytes": df.groupby("bin")["frame.len"].sum(),
        "throughput_down": bytes_g["down"] * 8 / BIN_SECONDS / 1e6,
        "throughput_up": bytes_g["up"] * 8 / BIN_SECONDS / 1e6,
    })
    thr["throughput_total"] = thr["throughput_down"] + thr["throughput_up"]

    all_bins = pd.RangeIndex(0, int(df["bin"].max()) + 1, name="bin")
    out = pd.DataFrame(index=all_bins).join([thr, rtt_df, re_df, dns_df])
    for c in COUNT_COLS:
        if c not in out:
            out[c] = 0
    out[COUNT_COLS] = out[COUNT_COLS].fillna(0).astype(int)
    for c in ("rtt_mean", "rtt_max", "rtt_p95", "retrans_rate", "dns_mean", "dns_max",
              "throughput_down", "throughput_up", "throughput_total", "bytes"):
        if c not in out:
            out[c] = np.nan
    # 표본이 너무 적은 구간의 RTT 는 신뢰 불가 -> NaN
    few = out["rtt_n"] < MIN_RTT_SAMPLES
    out.loc[few, ["rtt_mean", "rtt_max", "rtt_p95"]] = np.nan
    out["t_min"] = out.index * (BIN_SECONDS / 60)
    return out.reset_index()


def protocol_group(name: str) -> str:
    for grp, members in PROTOCOL_GROUPS.items():
        if name in members:
            return grp
    return "Other"


def protocol_mix(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """프로토콜 그룹별 바이트/패킷 비중 (전체) + 1분 구간별 Mbps."""
    df = add_bins(df)
    df["group"] = df["protocol"].fillna("Other").astype(str).map(protocol_group)
    total = df.groupby("group").agg(bytes=("frame.len", "sum"), pkts=("frame.len", "size"))
    total["bytes_pct"] = total["bytes"] / total["bytes"].sum() * 100
    total["pkts_pct"] = total["pkts"] / total["pkts"].sum() * 100
    total = total.sort_values("bytes", ascending=False)
    per_bin = df.pivot_table(index="bin", columns="group", values="frame.len", aggfunc="sum", fill_value=0)
    per_bin = per_bin * 8 / BIN_SECONDS / 1e6  # Mbps
    return total.reset_index(), per_bin


def top_talkers(df: pd.DataFrame, my_ip: str, n: int = 10) -> pd.DataFrame:
    """내 호스트와 통신한 상대 IP 상위 n 개 (바이트 기준). 마스킹은 호출부에서."""
    peer = np.where(df["ip.src"] == my_ip, df["ip.dst"], df["ip.src"])
    t = df.assign(peer=peer).groupby("peer")["frame.len"].agg(bytes="sum", pkts="size")
    t = t.drop(index=my_ip, errors="ignore").sort_values("bytes", ascending=False).head(n)
    t["bytes_pct"] = t["bytes"] / df["frame.len"].sum() * 100
    return t.reset_index()
