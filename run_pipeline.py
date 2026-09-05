"""전체 파이프라인: pcap -> tshark 필드 추출 -> 1분 집계 -> I-chart -> 그래프/요약.

사용:
    python run_pipeline.py --pcap captures/home_30min.pcapng
    python run_pipeline.py --csv data/packets.csv          # 추출 CSV 재사용
    python run_pipeline.py --pcap ... --my-ip 192.168.0.10  # 호스트 IP 수동 지정

results/ 에는 IP 가 마스킹된 집계 결과만 저장된다. raw pcap / packets.csv 는 data/, captures/ (gitignore).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.aggregate import aggregate_bins, protocol_mix, top_talkers
from src.config import DATA_DIR, RESULTS_DIR, SIGMA_K
from src.extract import extract_fields, guess_my_ip, load_packets
from src.mask import mask_ip
from src.spc import apply_i_chart, ooc_segments
from src.visualize import plot_protocol_mix, plot_retrans_ichart, plot_rtt_ichart


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", type=Path)
    ap.add_argument("--csv", type=Path, help="이미 추출한 packets.csv (pcap 대신)")
    ap.add_argument("--my-ip", type=str, default=None)
    ap.add_argument("--out", type=Path, default=RESULTS_DIR)
    args = ap.parse_args()

    if not args.pcap and not args.csv:
        ap.error("--pcap 또는 --csv 중 하나는 필요합니다.")

    csv_path = args.csv
    if args.pcap:
        csv_path = DATA_DIR / (args.pcap.stem + "_packets.csv")
        print(f"[1/5] tshark 필드 추출: {args.pcap} -> {csv_path}")
        extract_fields(args.pcap, csv_path)

    print(f"[2/5] 패킷 로드: {csv_path}")
    df = load_packets(csv_path)
    my_ip = args.my_ip or guess_my_ip(df)
    print(f"      패킷 {len(df):,}개, 내 호스트 = {mask_ip(my_ip)}")

    print("[3/5] 1분 구간 집계")
    bins = aggregate_bins(df, my_ip)
    total_mix, per_bin_mix = protocol_mix(df)

    print(f"[4/5] I-chart (±{SIGMA_K:g}σ)")
    bins, rtt_lim = apply_i_chart(bins, "rtt_mean")
    bins, re_lim = apply_i_chart(bins, "retrans_rate")
    rtt_segs = ooc_segments(bins, "rtt_mean")
    re_segs = ooc_segments(bins, "retrans_rate")

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    print(f"[5/5] 결과 저장 -> {out}/")
    bins.round(4).to_csv(out / "bins_1min.csv", index=False)
    total_mix.round(3).to_csv(out / "protocol_mix.csv", index=False)
    talk = top_talkers(df, my_ip)
    talk["peer"] = talk["peer"].map(mask_ip)  # 마스킹 후에만 저장
    talk.round(3).to_csv(out / "top_peers_masked.csv", index=False)

    plot_rtt_ichart(bins, rtt_lim, out / "rtt_ichart.png")
    plot_retrans_ichart(bins, re_lim, out / "retrans_ichart.png")
    plot_protocol_mix(total_mix, per_bin_mix, out / "protocol_mix.png")

    dur_s = float(df["t"].max() - df["t"].min())
    tcp = df[df["is_tcp"]]
    n_retrans = int((tcp["is_retrans"] | tcp["is_fast_retrans"]).sum())
    rtt_all = tcp[(tcp["ip.dst"] == my_ip) & tcp["ack_rtt"].notna()]["ack_rtt"] * 1000
    dns_all = df[df["is_dns_resp"] & df["dns_time"].notna()]["dns_time"] * 1000

    def _seg_info(segs, col):
        rows = []
        for s in segs:
            sub = bins[(bins["bin"] >= s["start_bin"]) & (bins["bin"] <= s["end_bin"])]
            rows.append({**s,
                         "throughput_total_mbps": round(float(sub["throughput_total"].mean()), 3),
                         "throughput_down_mbps": round(float(sub["throughput_down"].mean()), 3),
                         "rtt_mean_ms": round(float(sub["rtt_mean"].mean()), 2) if sub["rtt_mean"].notna().any() else None,
                         "retrans_rate_pct": round(float(sub["retrans_rate"].mean()), 3),
                         "dns_mean_ms": round(float(sub["dns_mean"].mean()), 2) if sub["dns_mean"].notna().any() else None})
        return rows

    summary = {
        "my_host": mask_ip(my_ip),
        "packets_total": int(len(df)),
        "bytes_total": int(df["frame.len"].sum()),
        "duration_sec": round(dur_s, 1),
        "duration_min": round(dur_s / 60, 2),
        "bins": int(len(bins)),
        "tcp_packets": int(len(tcp)),
        "tcp_retrans_packets": n_retrans,
        "tcp_retrans_rate_pct_overall": round(n_retrans / max(len(tcp), 1) * 100, 4),
        "tcp_spurious_retrans_packets": int(tcp["is_spurious"].sum()),
        "rtt_samples": int(len(rtt_all)),
        "rtt_mean_ms": round(float(rtt_all.mean()), 3) if len(rtt_all) else None,
        "rtt_median_ms": round(float(rtt_all.median()), 3) if len(rtt_all) else None,
        "rtt_p95_ms": round(float(rtt_all.quantile(0.95)), 3) if len(rtt_all) else None,
        "rtt_max_ms": round(float(rtt_all.max()), 3) if len(rtt_all) else None,
        "dns_responses": int(len(dns_all)),
        "dns_mean_ms": round(float(dns_all.mean()), 3) if len(dns_all) else None,
        "dns_p95_ms": round(float(dns_all.quantile(0.95)), 3) if len(dns_all) else None,
        "dns_max_ms": round(float(dns_all.max()), 3) if len(dns_all) else None,
        "throughput_mean_mbps": round(float(bins["throughput_total"].mean()), 3),
        "throughput_max_1min_mbps": round(float(bins["throughput_total"].max()), 3),
        "ichart": {
            "rtt_mean": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in rtt_lim.items()},
            "retrans_rate": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in re_lim.items()},
        },
        "ooc_rtt_bins": int(bins["rtt_mean_ooc"].sum()),
        "ooc_retrans_bins": int(bins["retrans_rate_ooc"].sum()),
        "ooc_rtt_segments": _seg_info(rtt_segs, "rtt_mean"),
        "ooc_retrans_segments": _seg_info(re_segs, "retrans_rate"),
        "protocol_mix_bytes_pct": {r["group"]: round(r["bytes_pct"], 2) for _, r in total_mix.iterrows()},
    }
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    pd.set_option("display.width", 160)
    print("\n=== 요약 ===")
    for k, v in summary.items():
        if not isinstance(v, (dict, list)):
            print(f"  {k}: {v}")
    print(f"  I-chart RTT: CL={rtt_lim['center']:.2f} ms, UCL={rtt_lim['ucl']:.2f} ms, 이탈 {summary['ooc_rtt_bins']}구간")
    print(f"  I-chart 재전송률: CL={re_lim['center']:.3f} %, UCL={re_lim['ucl']:.3f} %, 이탈 {summary['ooc_retrans_bins']}구간")


if __name__ == "__main__":
    main()
