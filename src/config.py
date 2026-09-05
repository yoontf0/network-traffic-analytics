"""파이프라인 공통 설정."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = ROOT / "captures"      # raw pcap (gitignore)
DATA_DIR = ROOT / "data"             # tshark 추출 CSV (gitignore, IP 포함)
RESULTS_DIR = ROOT / "results"       # 집계 결과 + 그래프 (IP 마스킹, 커밋 대상)

BIN_SECONDS = 60          # 집계 구간 (1분)
SIGMA_K = 3.0             # 관리한계 = CL ± k·σ
MIN_RTT_SAMPLES = 5       # 구간당 RTT 표본이 이보다 적으면 결측 처리
RTT_MAX_VALID_S = 3.0     # 이보다 큰 ack_rtt 는 네트워크 RTT 로 볼 수 없어(RTO 이미 발생) 무효 표본 처리

# tshark 로 뽑을 필드 (순서 = CSV 컬럼 순서)
TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "frame.len",
    "tcp.stream",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "dns.time",
    "dns.flags.response",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
]

# 프로토콜 구성 그래프에서 묶을 그룹
PROTOCOL_GROUPS = {
    "TLS/HTTPS": ("TLSv1.2", "TLSv1.3", "TLSv1", "TLSv1.1", "SSL", "HTTP", "HTTP2", "HTTP/JSON", "HTTP/XML"),
    "QUIC": ("QUIC", "HTTP3", "GQUIC"),
    "TCP (payload)": ("TCP",),
    "DNS": ("DNS", "MDNS", "LLMNR"),
    "UDP (other)": ("UDP", "STUN", "SSDP", "NBNS", "RTP", "RTCP"),
}
