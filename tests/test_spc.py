import numpy as np
import pandas as pd

from src.spc import apply_i_chart, i_chart_limits, ooc_segments


def test_limits_match_2_66_mr_bar():
    x = np.array([10.0, 12.0, 11.0, 13.0, 12.0, 11.0])
    lim = i_chart_limits(x, floor_at_zero=False)
    mr_bar = np.abs(np.diff(x)).mean()
    assert abs(lim["ucl"] - (x.mean() + 3 / 1.128 * mr_bar)) < 1e-9
    assert abs(lim["lcl"] - (x.mean() - 3 / 1.128 * mr_bar)) < 1e-9


def test_spike_detected_as_out_of_control():
    rng = np.random.default_rng(0)
    y = rng.normal(30, 1.0, 30)
    y[17] = 60.0  # 명백한 스파이크
    bins = pd.DataFrame({"bin": range(30), "t_min": range(30), "rtt_mean": y})
    out, lim = apply_i_chart(bins, "rtt_mean")
    assert out["rtt_mean_ooc"].sum() >= 1
    assert bool(out.loc[17, "rtt_mean_ooc"])
    segs = ooc_segments(out, "rtt_mean")
    assert any(s["start_bin"] <= 17 <= s["end_bin"] for s in segs)


def test_nan_bins_are_ignored():
    y = [1.0, np.nan, 1.1, 0.9, np.nan, 1.0]
    bins = pd.DataFrame({"bin": range(6), "t_min": range(6), "retrans_rate": y})
    out, lim = apply_i_chart(bins, "retrans_rate")
    assert lim["n"] == 4
    assert not out["retrans_rate_ooc"].iloc[1]
    assert lim["lcl"] >= 0.0
