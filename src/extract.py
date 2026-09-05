"""tshark 로 pcap 에서 필드를 추출해 CSV 로 저장 (data/ 아래, gitignore).

tshark -r <pcap> -n -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e ...
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from pathlib import Path

import pandas as pd

from .config import TSHARK_FIELDS

_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
]


def find_tshark() -> str:
    exe = shutil.which("tshark")
    if exe:
        return exe
    for c in _CANDIDATES:
        if os.path.exists(c):
            return c
    raise FileNotFoundError(
        "tshark 를 찾을 수 없습니다. Wireshark 를 설치하거나 PATH 에 추가하세요."
    )


def extract_fields(pcap: Path, out_csv: Path, tshark: str | None = None) -> Path:
    """pcap -> CSV (항상 새로 생성)."""
    tshark = tshark or find_tshark()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        tshark, "-r", str(pcap), "-n",  # -n: 이름 조회 안 함 (속도 + 프라이버시)
        "-T", "fields",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f",
    ]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    with open(out_csv, "w", encoding="utf-8", newline="") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark 실패 (rc={proc.returncode}):\n{proc.stderr[-2000:]}")
    return out_csv


def load_packets(csv_path: Path) -> pd.DataFrame:
    """추출 CSV 를 pandas 로 로드하고 타입을 정리한다."""
    df = pd.read_csv(csv_path, low_memory=False)
    # tshark 는 헤더를 소문자로 출력한다 (_ws.col.protocol)
    df = df.rename(columns={"_ws.col.Protocol": "protocol", "_ws.col.protocol": "protocol"})
    df["t"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0).astype(int)
    df["ack_rtt"] = pd.to_numeric(df["tcp.analysis.ack_rtt"], errors="coerce")
    df["dns_time"] = pd.to_numeric(df["dns.time"], errors="coerce")
    # FT_NONE 필드는 존재할 때만 값이 찍힌다 -> notna 로 판정
    for col, new in [
        ("tcp.analysis.retransmission", "is_retrans"),
        ("tcp.analysis.fast_retransmission", "is_fast_retrans"),
        ("tcp.analysis.spurious_retransmission", "is_spurious"),
    ]:
        df[new] = df[col].notna() & (df[col].astype(str).str.strip() != "")
    df["is_tcp"] = df["tcp.stream"].notna()
    # 불리언 필드는 "True"/"False" 또는 "1"/"0" 으로 찍힌다
    resp = df["dns.flags.response"].astype(str).str.strip().str.lower()
    df["is_dns_resp"] = resp.isin(["true", "1"])
    df = df.dropna(subset=["t"]).sort_values("t").reset_index(drop=True)
    return df


def guess_my_ip(df: pd.DataFrame) -> str:
    """가장 많이 등장하는 사설 IPv4 를 내 호스트로 추정한다."""
    counts = pd.concat([df["ip.src"], df["ip.dst"]]).dropna().value_counts()
    for ip, _ in counts.items():
        cand = str(ip).split(",")[0]
        try:
            a = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if a.version == 4 and a.is_private:
            return cand
    raise ValueError("사설 IP 를 찾지 못했습니다. --my-ip 로 직접 지정하세요.")
