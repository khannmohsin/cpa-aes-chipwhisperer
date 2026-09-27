"""Offline tests for the CPA core in attack.py (numpy only, no hardware)."""

import numpy as np
import pytest

from attack import (
    HW, aes_internal, byte_correlations, confirms_device,
    correlate, main, parse_args, plot_correlation, plot_traces_needed,
    recover_key, sbox, write_key_report,
)
from conftest import make_traces


# ---------------------------------------------------------------------------
# The power model primitives
# ---------------------------------------------------------------------------

def test_sbox_reference_values():
    assert len(sbox) == 256
    assert sbox[0x00] == 0x63
    assert sbox[0xff] == 0x16
    # The tutorial's own sanity checks
    assert HW[aes_internal(0xA1, 0x79)] == 3
    assert HW[aes_internal(0x22, 0xB1)] == 5


def test_hw_table():
    assert HW[0] == 0
    assert HW[0xFF] == 8
    assert HW[0x0F] == 4


# ---------------------------------------------------------------------------
# correlate()
# ---------------------------------------------------------------------------

def test_correlate_matches_manual_pearson():
    rng = np.random.default_rng(0)
    traces = rng.normal(size=(20, 30))
    hyp = rng.normal(size=20)
    t_bar = traces.mean(axis=0)
    o_t = np.sqrt(((traces - t_bar) ** 2).sum(axis=0))
    h_bar = hyp.mean()
    o_h = np.sqrt(((hyp - h_bar) ** 2).sum())
    cov = ((traces - t_bar) * (hyp - h_bar)[:, None]).sum(axis=0)
    np.testing.assert_allclose(correlate(traces, hyp), cov / (o_t * o_h))


def test_correlate_flat_sample_column_is_zero():
    """Regression: a zero-variance trace column used to yield NaN (0/0) and
    poison the max() for the whole key byte; it must now be 0.0."""
    rng = np.random.default_rng(1)
    traces = rng.normal(size=(20, 10))
    traces[:, 5] = 3.0                    # exactly constant column
    hyp = rng.normal(size=20)
    corr = correlate(traces, hyp)
    assert np.isfinite(corr).all()
    assert corr[5] == 0.0


def test_correlate_flat_hypothesis_is_zero():
    rng = np.random.default_rng(2)
    traces = rng.normal(size=(20, 10))
    corr = correlate(traces, np.full(20, 2.0))
    assert np.isfinite(corr).all()
    assert (corr == 0.0).all()


def test_correlate_perfect_linear_is_one():
    rng = np.random.default_rng(3)
    hyp = rng.normal(size=20)
    traces = rng.normal(size=(20, 10))
    traces[:, 3] = 2.0 * hyp + 1.0        # exact linear relationship
    corr = correlate(traces, hyp)
    assert corr[3] == pytest.approx(1.0, abs=1e-12)


# ---------------------------------------------------------------------------
# byte_correlations() / recover_key()
# ---------------------------------------------------------------------------

def test_byte_correlations_recovers_byte():
    traces, pts, key = make_traces(n=100, seed=7)
    best = byte_correlations(traces, pts, 0)
    assert np.isfinite(best).all()
    assert int(np.argmax(best)) == int(key[0])
    assert best[int(key[0])] > 0.5


def test_byte_correlations_flat_baseline_regression():
    """The pre-trigger flat baseline used to turn EVERY key guess into NaN and
    recover 0x00. With the fix the correct byte still wins."""
    traces, pts, key = make_traces(n=60, seed=11, flat_prefix=300)
    best = byte_correlations(traces, pts, 0)
    assert np.isfinite(best).all()
    assert int(np.argmax(best)) == int(key[0])


def test_byte_correlations_ntraces_truncation():
    traces, pts, key = make_traces(n=100, seed=3)
    b_25 = byte_correlations(traces, pts, 0, ntraces=25)
    b_slice = byte_correlations(traces[:25], pts[:25], 0)
    np.testing.assert_array_equal(b_25, b_slice)
    assert int(np.argmax(b_25)) == int(key[0])


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_recover_key_full(seed):
    traces, pts, key = make_traces(n=100, seed=seed)
    recovered = recover_key(traces, pts)
    np.testing.assert_array_equal(recovered, key)


def test_recover_key_few_traces():
    traces, pts, key = make_traces(n=20, seed=5)
    recovered = recover_key(traces, pts)
    np.testing.assert_array_equal(recovered, key)


# ---------------------------------------------------------------------------
# confirms_device()
# ---------------------------------------------------------------------------

def test_confirms_device_true_and_false():
    pytest.importorskip("Crypto.Cipher")
    from Crypto.Cipher import AES

    rng = np.random.default_rng(9)
    plaintexts = rng.integers(0, 256, (50, 16), dtype=np.uint8)
    key = rng.integers(0, 256, 16, dtype=np.uint8)
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    cts = [cipher.encrypt(bytes(p)) for p in plaintexts]

    assert confirms_device(key, plaintexts, cts) is True
    wrong = key.copy()
    wrong[0] ^= 0x01
    assert confirms_device(wrong, plaintexts, cts) is False


# ---------------------------------------------------------------------------
# write_key_report()
# ---------------------------------------------------------------------------

def test_write_key_report_match(tmp_path):
    real = np.full(16, 0x2B, dtype=np.uint8)
    write_key_report(real, real, str(tmp_path))
    txt = (tmp_path / "recovered_key.txt").read_text()
    assert "MATCH: yes" in txt
    assert "Recovered key: " + bytes(real).hex() in txt
    assert "byte  recovered  real  correct?" in txt.replace("  ", " ") or \
        "byte  recovered  real  correct?" in txt


def test_write_key_report_mismatch(tmp_path):
    real = np.full(16, 0x2B, dtype=np.uint8)
    recovered = real.copy()
    recovered[3] ^= 0xFF
    write_key_report(recovered, real, str(tmp_path))
    txt = (tmp_path / "recovered_key.txt").read_text()
    assert "MATCH: no" in txt
    assert "NO" in txt


# ---------------------------------------------------------------------------
# plots
# ---------------------------------------------------------------------------

def test_plots_written(tmp_path):
    pytest.importorskip("matplotlib")
    traces, pts, key = make_traces(n=40, seed=4)
    plot_correlation(traces, pts, key, str(tmp_path))
    plot_traces_needed(traces, pts, key, str(tmp_path))
    assert (tmp_path / "correlation_plot.png").stat().st_size > 0
    assert (tmp_path / "traces_needed.png").stat().st_size > 0


def test_plot_traces_needed_skips_under_ten(tmp_path):
    pytest.importorskip("matplotlib")
    traces, pts, key = make_traces(n=5, seed=6)
    plot_traces_needed(traces, pts, key, str(tmp_path))
    assert not (tmp_path / "traces_needed.png").exists()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_parse_args_defaults():
    args = parse_args([])
    assert args.data_dir == "data"
    assert args.results_dir == "results"
    assert args.ntraces is None
    assert args.no_plots is False


def test_parse_args_overrides():
    args = parse_args(["--ntraces", "7", "--no-plots",
                       "--data-dir", "x", "--results-dir", "y"])
    assert args.ntraces == 7
    assert args.no_plots is True
    assert args.data_dir == "x"
    assert args.results_dir == "y"


def test_main_roundtrip(tmp_path):
    traces, pts, key = make_traces(n=80, seed=8)
    d = tmp_path / "data"
    d.mkdir()
    np.save(d / "traces.npy", traces)
    np.save(d / "plaintexts.npy", pts)
    np.save(d / "key.npy", key)
    r = tmp_path / "results"

    main(["--data-dir", str(d), "--results-dir", str(r),
          "--ntraces", "50", "--no-plots"])

    txt = (r / "recovered_key.txt").read_text()
    assert "MATCH: yes" in txt
    assert not (r / "correlation_plot.png").exists()


def test_main_rejects_zero_ntraces(tmp_path):
    traces, pts, key = make_traces(n=10, seed=8)
    d = tmp_path / "data"
    d.mkdir()
    np.save(d / "traces.npy", traces)
    np.save(d / "plaintexts.npy", pts)
    np.save(d / "key.npy", key)
    with pytest.raises(SystemExit):
        main(["--data-dir", str(d), "--ntraces", "0", "--no-plots"])