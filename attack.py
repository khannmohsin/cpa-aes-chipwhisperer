"""
attack.py - Turn the CPA run into the three teaching artifacts:
  results/recovered_key.txt      recovered vs real key, MATCH, per-byte table
  results/correlation_plot.png   byte 0: correlation for all 256 key guesses
  results/traces_needed.png      correct guess separating from wrong ones

It loads the traces captured by capture.py and reuses the same correlation
math as run_cpa_from_notebook.py (NewAE's tutorial CPA).

The correlation core only needs numpy, so it can be imported and tested
anywhere; matplotlib (plots) and tqdm (progress bar) are optional extras.
"""

import argparse
import os

import numpy as np

try:
    from tqdm import trange
except ImportError:          # tqdm is optional; a plain range is fine
    trange = range

DATA_DIR, RESULTS_DIR = "data", "results"
ORANGE, GREY = "tab:orange", "lightgrey"

# The AES S-box (from run_cpa_from_notebook.py / the AES standard).
sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Number of 1-bits (Hamming weight) of every byte 0..255.
HW = [bin(n).count("1") for n in range(256)]


def aes_internal(pt_byte, key_byte):
    """The value the chip computes in round 1: Sbox[plaintext XOR key]."""
    return sbox[pt_byte ^ key_byte]


def correlate(traces, hyp, t_bar=None, o_t=None):
    """Pearson correlation of one hypothesis column against every trace sample.

    Returns one correlation per sample; we keep the largest absolute value.

    Sample columns (or a hypothesis) with zero variance get a correlation of
    0.0: a flat signal carries no information, and 0/0 would otherwise turn
    into NaN, which poiisons the max() below and silently breaks the attack
    (every key guess ends up NaN, argmax returns 0). t_bar / o_t may be
    passed in when the caller already computed them (see byte_correlations).
    """
    if t_bar is None:
        t_bar = np.mean(traces, axis=0)
    if o_t is None:
        o_t = np.sqrt(np.sum((traces - t_bar) ** 2, axis=0))
    h_bar = np.mean(hyp)
    o_h = np.sqrt(np.sum((hyp - h_bar) ** 2))
    cov = np.sum((traces - t_bar) * (hyp - h_bar)[:, None], axis=0)
    denom = o_t * o_h
    corr = np.zeros_like(denom)
    np.divide(cov, denom, out=corr, where=denom > 0)
    return corr


def byte_correlations(traces, plaintexts, bnum, ntraces=None):
    """Best absolute correlation for each of the 256 guesses of key byte bnum.

    The trace mean and standard deviation do not depend on the key guess, so
    they are computed once here and reused by correlate() for all 256
    guesses (the same hoisting the NewAE tutorial does).
    """
    if ntraces is None:
        ntraces = len(traces)
    t = traces[:ntraces]
    pt = plaintexts[:ntraces, bnum]
    t_bar = np.mean(t, axis=0)
    o_t = np.sqrt(np.sum((t - t_bar) ** 2, axis=0))
    best = np.zeros(256)
    for kguess in range(256):
        hyp = np.array([HW[aes_internal(p, kguess)] for p in pt], dtype=float)
        best[kguess] = np.max(np.abs(correlate(t, hyp, t_bar, o_t)))
    return best


def recover_key(traces, plaintexts):
    """Best guess for all 16 key bytes."""
    guess = np.zeros(16, dtype=np.uint8)
    for bnum in trange(16, desc="recovering key"):
        guess[bnum] = np.argmax(byte_correlations(traces, plaintexts, bnum))
    return guess


def confirms_device(recovered, plaintexts, device_ciphertexts):
    """Independent check: does the recovered key reproduce the chip's ciphertexts?

    This trusts neither our stored key nor our CPA code. It encrypts each
    plaintext with the recovered key using a separate AES library
    (PyCryptodome) and compares to what the hardware really output.
    """
    from Crypto.Cipher import AES

    cipher = AES.new(bytes(recovered), AES.MODE_ECB)
    for pt, ct_device in zip(plaintexts, device_ciphertexts):
        if cipher.encrypt(bytes(pt)) != ct_device:
            return False
    return True


def write_key_report(recovered, real, results_dir=RESULTS_DIR):
    os.makedirs(results_dir, exist_ok=True)
    match = np.array_equal(recovered, real)
    with open(os.path.join(results_dir, "recovered_key.txt"), "w") as f:
        f.write("Recovered key: " + bytes(recovered).hex() + "\n")
        f.write("Real key:      " + bytes(real).hex() + "\n")
        f.write("MATCH: " + ("yes" if match else "no") + "\n\n")
        f.write("byte  recovered  real  correct?\n")
        for i in range(16):
            ok = "yes" if recovered[i] == real[i] else "NO"
            f.write(f"{i:4d}       {recovered[i]:02x}     {real[i]:02x}     {ok}\n")
    print("wrote " + os.path.join(results_dir, "recovered_key.txt"),
          " (MATCH:", "yes)" if match else "no)")


def _plt():
    """matplotlib is only needed for the plots; import it lazily."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def plot_correlation(traces, plaintexts, real, results_dir=RESULTS_DIR):
    """Byte 0: correlation of all 256 guesses, correct one highlighted."""
    corr = byte_correlations(traces, plaintexts, 0)
    correct = real[0]
    plt = _plt()
    plt.figure(figsize=(10, 4), facecolor="white")
    plt.bar(range(256), corr, color=GREY, width=1.0)
    plt.bar([correct], [corr[correct]], color=ORANGE, width=2.0,
            label=f"correct guess (0x{correct:02x})")
    plt.title("Byte 0: correlation for every key guess")
    plt.xlabel("Key byte guess (0-255)")
    plt.ylabel("Best absolute correlation")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "correlation_plot.png"), dpi=150)
    plt.close()
    print("wrote " + os.path.join(results_dir, "correlation_plot.png"))


def plot_traces_needed(traces, plaintexts, real, results_dir=RESULTS_DIR):
    """Byte 0: how the correct guess separates from the wrong ones as traces pile up."""
    if len(traces) < 10:
        print(f"fewer than 10 traces (have {len(traces)}); skipping traces_needed plot")
        return
    counts = list(range(10, len(traces) + 1, 10))
    correct = real[0]
    correct_line, wrong_lines = [], []
    for n in counts:
        corr = byte_correlations(traces, plaintexts, 0, ntraces=n)
        correct_line.append(corr[correct])
        wrong = np.delete(corr, correct)
        wrong_lines.append(wrong)

    plt = _plt()
    plt.figure(figsize=(10, 4), facecolor="white")
    for i in range(255):                       # every wrong guess, in grey
        plt.plot(counts, [w[i] for w in wrong_lines], color=GREY, linewidth=0.5)
    plt.plot(counts, correct_line, color=ORANGE, linewidth=2.0,
             label=f"correct guess (0x{correct:02x})")
    plt.title("Byte 0: correct guess wins as traces pile up")
    plt.xlabel("Number of traces used")
    plt.ylabel("Best absolute correlation")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "traces_needed.png"), dpi=150)
    plt.close()
    print("wrote " + os.path.join(results_dir, "traces_needed.png"))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Correlation Power Analysis on captured AES-128 traces "
                    "(ChipWhisperer-Lite teaching demo).",
    )
    parser.add_argument("--data-dir", default=DATA_DIR,
                        help="folder with traces.npy, plaintexts.npy, key.npy "
                             f"(default: {DATA_DIR})")
    parser.add_argument("--results-dir", default=RESULTS_DIR,
                        help="folder for the report and plots "
                             f"(default: {RESULTS_DIR})")
    parser.add_argument("--ntraces", type=int, default=None,
                        help="use only the first N traces (default: all of them)")
    parser.add_argument("--no-plots", action="store_true",
                        help="skip the PNG plots, write the key report only")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.ntraces is not None and args.ntraces <= 0:
        raise SystemExit("--ntraces must be at least 1")
    traces = np.load(os.path.join(args.data_dir, "traces.npy"))
    plaintexts = np.load(os.path.join(args.data_dir, "plaintexts.npy"))
    real = np.load(os.path.join(args.data_dir, "key.npy"))

    if args.ntraces is not None:
        traces = traces[:args.ntraces]
        plaintexts = plaintexts[:args.ntraces]
        print(f"using the first {len(traces)} traces")
    print(f"loaded {traces.shape[0]} traces of {traces.shape[1]} samples")

    recovered = recover_key(traces, plaintexts)
    write_key_report(recovered, real, args.results_dir)
    if not args.no_plots:
        plot_correlation(traces, plaintexts, real, args.results_dir)
        plot_traces_needed(traces, plaintexts, real, args.results_dir)
    print("done")


if __name__ == "__main__":
    main()