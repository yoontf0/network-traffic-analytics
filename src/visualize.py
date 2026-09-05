"""결과 그래프 3장 (matplotlib, PNG).

1. rtt_ichart.png          : 1분 평균 RTT 시계열 + I-chart 관리한계, 이탈 구간 표시
2. retrans_ichart.png      : 1분 재전송률 시계열 + I-chart 관리한계, 이탈 구간 표시
3. protocol_mix.png        : 프로토콜 그룹별 트래픽 구성 (전체 비중 + 1분 구간별 Mbps)

색상: 계열 1색(파랑), 관리한계 회색, 이탈점 = 상태색(빨강) + 마커 모양으로 이중 인코딩.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
STATUS_CRITICAL = "#e34948"
GRID = "#e6e5e1"
TEXT = "#0b0b0b"
TEXT2 = "#52514e"
SURFACE = "#fcfcfb"

plt.rcParams.update({
    "font.family": ["Malgun Gothic", "DejaVu Sans"],
    "axes.unicode_minus": False,
    "axes.edgecolor": GRID,
    "axes.labelcolor": TEXT2,
    "xtick.color": TEXT2,
    "ytick.color": TEXT2,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "figure.dpi": 130,
})


ACTIVITY_FILL = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]


def _shade_activities(ax, activities):
    """activities: [{"start_min", "end_min", "label"}] -> 배경 음영 + 상단 라벨."""
    if not activities:
        return
    for i, a in enumerate(activities):
        c = ACTIVITY_FILL[i % len(ACTIVITY_FILL)]
        ax.axvspan(a["start_min"] - 0.5, a["end_min"] - 0.5, color=c, alpha=0.07, linewidth=0)
        ax.text((a["start_min"] + a["end_min"]) / 2 - 0.5, 0.98, a["label"], transform=ax.get_xaxis_transform(),
                ha="center", va="top", fontsize=8.5, color=TEXT2)


def _ichart(ax, bins: pd.DataFrame, col: str, lim: dict, ylabel: str, title: str, unit: str, activities=None):
    _shade_activities(ax, activities)
    x = bins["t_min"]
    y = bins[col]
    ax.plot(x, y, color=SERIES[0], linewidth=2, marker="o", markersize=4, label=ylabel)
    ax.axhline(lim["center"], color=TEXT2, linewidth=1, linestyle="-")
    ax.axhline(lim["ucl"], color=TEXT2, linewidth=1, linestyle="--")
    if lim["lcl"] > 0:
        ax.axhline(lim["lcl"], color=TEXT2, linewidth=1, linestyle="--")
    xmax = float(x.max()) if len(x) else 1.0
    ax.text(xmax, lim["center"], f" CL {lim['center']:.2f}{unit}", va="center", ha="left", fontsize=8, color=TEXT2)
    ax.text(xmax, lim["ucl"], f" UCL {lim['ucl']:.2f}{unit}", va="center", ha="left", fontsize=8, color=TEXT2)
    if lim["lcl"] > 0:
        ax.text(xmax, lim["lcl"], f" LCL {lim['lcl']:.2f}{unit}", va="center", ha="left", fontsize=8, color=TEXT2)

    ooc = bins[bins[f"{col}_ooc"]]
    if len(ooc):
        ax.scatter(ooc["t_min"], ooc[col], s=90, marker="^", color=STATUS_CRITICAL,
                   edgecolor=SURFACE, linewidth=1.5, zorder=5, label=f"3σ 이탈 ({len(ooc)}구간)")
        for _, r in ooc.iterrows():
            ax.annotate(f"{r[col]:.1f}", (r["t_min"], r[col]), textcoords="offset points",
                        xytext=(0, 9), ha="center", fontsize=8, color=TEXT)
    ax.set_xlabel("캡처 경과 시간 [분]")
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left", fontsize=12, color=TEXT, fontweight="bold")
    ax.legend(loc="best", bbox_to_anchor=(0, 0, 1, 0.88), frameon=True, framealpha=0.85, edgecolor=GRID, fontsize=9)
    ax.margins(x=0.02)
    ax.set_xlim(left=-0.5, right=xmax + 0.5)


def plot_rtt_ichart(bins: pd.DataFrame, lim: dict, out: Path, activities=None):
    fig, ax = plt.subplots(figsize=(11, 4.2))
    _ichart(ax, bins, "rtt_mean", lim, "평균 RTT [ms]",
            "TCP RTT (1분 평균) - I-Chart, 중심선 ± 3σ", " ms", activities)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def plot_retrans_ichart(bins: pd.DataFrame, lim: dict, out: Path, activities=None):
    fig, ax = plt.subplots(figsize=(11, 4.2))
    _ichart(ax, bins, "retrans_rate", lim, "TCP 재전송률 [%]",
            "TCP 재전송률 (1분 구간) - I-Chart, 중심선 ± 3σ", " %", activities)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def plot_protocol_mix(total: pd.DataFrame, per_bin: pd.DataFrame, out: Path):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.4), gridspec_kw={"width_ratios": [1, 2.2]})
    order = list(total["group"])
    colors = {g: SERIES[i % len(SERIES)] for i, g in enumerate(order)}

    # 왼쪽: 전체 바이트 비중 (가로 막대)
    ax1.barh(order[::-1], total["bytes_pct"][::-1], color=[colors[g] for g in order[::-1]], height=0.6)
    for i, (g, p) in enumerate(zip(order[::-1], total["bytes_pct"][::-1])):
        ax1.text(p + 0.5, i, f"{p:.1f}%", va="center", fontsize=9, color=TEXT)
    ax1.set_xlabel("전체 바이트 비중 [%]")
    ax1.set_xlim(0, max(100, float(total["bytes_pct"].max()) + 12))
    ax1.set_title("프로토콜별 트래픽 구성", loc="left", fontsize=12, color=TEXT, fontweight="bold")
    ax1.grid(axis="y", visible=False)

    # 오른쪽: 1분 구간별 Mbps (누적 영역)
    cols = [g for g in order if g in per_bin.columns]
    x = per_bin.index.to_numpy() * 1.0
    ax2.stackplot(x, [per_bin[c].to_numpy() for c in cols], labels=cols,
                  colors=[colors[c] for c in cols], alpha=0.9)
    ax2.set_xlabel("캡처 경과 시간 [분]")
    ax2.set_ylabel("처리량 [Mbps]")
    ax2.set_title("1분 구간별 처리량 (프로토콜 그룹 누적)", loc="left", fontsize=12, color=TEXT, fontweight="bold")
    ax2.legend(loc="upper left", frameon=False, fontsize=9, ncol=2)
    ax2.margins(x=0)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
