"""Individuals control chart (I-Chart), 3-sigma 관리한계.

sigma 추정은 이동범위(Moving Range) 기반: sigma_hat = MR_bar / d2 (n=2 -> d2 = 1.128)
    UCL = CL + 3*sigma_hat = CL + 2.66*MR_bar
    LCL = CL - 3*sigma_hat = CL - 2.66*MR_bar  (음수가 될 수 없는 지표는 0 으로 절단)

반도체 공정 SPC (etch-doe-optimizer/src/spc.py) 와 같은 방식을
네트워크 품질 지표(RTT, 재전송률)에 그대로 적용한다.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .config import SIGMA_K

D2_N2 = 1.128


def i_chart_limits(values, k: float = SIGMA_K, floor_at_zero: bool = True) -> dict:
    x = pd.Series(values, dtype=float).dropna().to_numpy()
    if len(x) < 2:
        nan = float("nan")
        return {"center": nan, "sigma_hat": nan, "mr_bar": nan, "ucl": nan, "lcl": nan, "n": int(len(x))}
    mr = np.abs(np.diff(x))
    mr_bar = float(mr.mean())
    sigma_hat = mr_bar / D2_N2
    center = float(x.mean())
    lcl = center - k * sigma_hat
    if floor_at_zero:
        lcl = max(lcl, 0.0)
    return {
        "center": center,
        "sigma_hat": sigma_hat,
        "mr_bar": mr_bar,
        "ucl": center + k * sigma_hat,
        "lcl": lcl,
        "n": int(len(x)),
    }


def apply_i_chart(
    bins: pd.DataFrame,
    col: str,
    k: float = SIGMA_K,
    upper_only: bool = True,
    baseline_mask: pd.Series | None = None,
    suffix: str = "",
) -> tuple[pd.DataFrame, dict]:
    """bins[col] 에 I-chart 적용. `<col>_ooc<suffix>` (out-of-control) 불리언 컬럼 추가.

    upper_only=True: RTT/재전송률처럼 '낮을수록 좋은' 지표는 UCL 초과만 품질 이상으로 본다
    (LCL 아래 = 평소보다 좋은 상태이므로 경보 대상이 아님).
    baseline_mask: 주어지면 관리한계를 그 구간(Phase I, 정상 기준선)에서만 추정하고
    전체 구간에 적용한다(Phase II). None 이면 전체 구간에서 추정(자기 자신 대비).
    """
    src = bins[col] if baseline_mask is None else bins.loc[baseline_mask, col]
    lim = i_chart_limits(src, k=k)
    lim["baseline_bins"] = int(src.notna().sum())
    out = bins.copy()
    v = out[col]
    if upper_only:
        out[f"{col}_ooc{suffix}"] = v.notna() & (v > lim["ucl"])
    else:
        out[f"{col}_ooc{suffix}"] = v.notna() & ((v > lim["ucl"]) | (v < lim["lcl"]))
    return out, lim


def ooc_segments(bins: pd.DataFrame, col: str) -> list[dict]:
    """연속된 이탈 구간을 묶어서 반환."""
    flag = bins[f"{col}_ooc"].to_numpy()
    segs = []
    i = 0
    while i < len(flag):
        if flag[i]:
            j = i
            while j + 1 < len(flag) and flag[j + 1]:
                j += 1
            sub = bins.iloc[i:j + 1]
            segs.append({
                "start_bin": int(bins["bin"].iloc[i]),
                "end_bin": int(bins["bin"].iloc[j]),
                "start_min": float(bins["t_min"].iloc[i]),
                "end_min": float(bins["t_min"].iloc[j] + 1),
                "peak": float(sub[col].max()),
                "n_bins": int(j - i + 1),
            })
            i = j + 1
        else:
            i += 1
    return segs
