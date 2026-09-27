"""
capture.py - Record power traces from a ChipWhisperer-Lite + XMEGA target
while it runs AES-128 encryptions.

Written for chipwhisperer 6.0.0.

Steps:
  1. Connect to the scope (the measuring board) and the target (the XMEGA chip).
  2. Flash the unprotected AES firmware onto the target.
  3. Choose one fixed secret key and many random plaintexts.
  4. For each plaintext, ask the target to encrypt it and record the power used.
  5. Save everything to the data/ folder.

The chipwhisperer SDK is imported lazily, inside the functions that need the
hardware, so `import capture` works even on machines without it installed
(capture_pairs() is reused by the verification scripts for this reason).
"""

import os
import sys
import importlib

import numpy as np

# ---------------------------------------------------------------------------
# Settings you may want to change (or pass as command-line flags)
# ---------------------------------------------------------------------------
NUM_TRACES  = 200      # how many encryptions to record
NUM_SAMPLES = 5000     # samples per trace (covers the first AES round)
GAIN        = 25       # amplifier gain in dB (higher = bigger signal)

# Where the compiled AES firmware lives (built from the repo copy in ./chipwhisperer)
FIRMWARE_PATH = os.path.join(
    "chipwhisperer", "firmware", "mcu", "simpleserial-aes",
    "simpleserial-aes-CWLITEXMEGA.hex",
)

DATA_DIR    = "data"
RESULTS_DIR = "results"


def print_versions():
    """Check that each needed package is installed and print its version."""
    print("Step 0: checking packages")
    for name in ["chipwhisperer", "numpy", "matplotlib", "tqdm"]:
        try:
            module = importlib.import_module(name)
            print(f"  {name:14s} {module.__version__}")
        except ImportError:
            print(f"  {name} is NOT installed. Run: pip install {name}")
            sys.exit(1)


def connect(gain=GAIN, samples=NUM_SAMPLES):
    """Step 1: find the ChipWhisperer and connect to the scope and target."""
    import chipwhisperer as cw

    print("Step 1: connecting to the ChipWhisperer-Lite")
    try:
        scope = cw.scope()
    except Exception:
        print("\n  Could not find the ChipWhisperer.")
        print("  Please check the USB cable is plugged in, then try again.\n")
        sys.exit(1)

    scope.default_setup()               # sensible clock, trigger and serial settings
    scope.gain.db = gain                # amplify the tiny power signal
    scope.adc.samples = samples         # how many points to record per trace
    target = cw.target(scope)           # serial link to the XMEGA
    print(f"  connected (gain = {gain} dB, samples = {samples})")
    return scope, target


def flash_firmware(scope, firmware_path=FIRMWARE_PATH):
    """Step 2: load the plain (unprotected) AES program onto the XMEGA."""
    import chipwhisperer as cw

    print("Step 2: flashing the AES firmware")
    if not os.path.exists(firmware_path):
        print(f"\n  Firmware not found at {firmware_path}")
        print("  Build it first (see README.md, 'Build the firmware').\n")
        sys.exit(1)                     # main() still disconnects cleanly
    cw.program_target(scope, cw.programmers.XMEGAProgrammer, firmware_path)
    print("  firmware flashed")


def record_traces(scope, target):
    """Steps 3 and 4: fixed key, random plaintexts, record one trace per encryption."""
    import chipwhisperer as cw
    from tqdm import tqdm

    print("Step 3: choosing one fixed key and random plaintexts")
    ktp = cw.ktp.Basic()                # ChipWhisperer's key/plaintext generator:
                                        # fixed key by default, random plaintext each time

    print(f"Step 4: recording {NUM_TRACES} traces")
    traces, plaintexts = [], []
    key = None
    for _ in tqdm(range(NUM_TRACES)):
        key, text = ktp.next()          # same key every time, new plaintext
        trace = cw.capture_trace(scope, target, text, key)
        if trace is None:               # the capture timed out; skip this one
            continue
        traces.append(trace.wave)       # the power samples
        plaintexts.append(list(trace.textin))

    print(f"  kept {len(traces)} good traces")
    if len(traces) == 0:
        print("  No traces were captured. Check the target board is seated properly.")
        sys.exit(1)
    return np.array(traces), np.array(plaintexts, dtype=np.uint8), np.array(list(key), dtype=np.uint8)


def capture_pairs(scope, target, key, n):
    """Record n traces of random plaintexts, all encrypted under `key`.

    We also keep the chip's own ciphertext (textout) for the independent
    verification checks in cpa_multikey.py and verify_recovery.py.
    """
    import chipwhisperer as cw

    traces, plaintexts, ciphertexts = [], [], []
    for i in range(n):
        text = bytearray(np.random.randint(0, 256, 16, dtype=np.uint8).tolist())
        # always_send_key on the first trace makes sure the target loads our key.
        trace = cw.capture_trace(scope, target, text, key,
                                 always_send_key=(i == 0))
        if trace is None:
            continue
        traces.append(trace.wave)
        plaintexts.append(list(trace.textin))
        ciphertexts.append(bytes(trace.textout))   # what the hardware actually output
    return np.array(traces), np.array(plaintexts, dtype=np.uint8), ciphertexts


def save_data(traces, plaintexts, key):
    """Steps 5 and 6: save the numbers, plus a human-readable log."""
    print("Step 5: saving traces.npy, plaintexts.npy, key.npy")
    os.makedirs(DATA_DIR, exist_ok=True)
    np.save(os.path.join(DATA_DIR, "traces.npy"), traces)
    np.save(os.path.join(DATA_DIR, "plaintexts.npy"), plaintexts)
    np.save(os.path.join(DATA_DIR, "key.npy"), key)

    print("Step 6: writing input_log.txt")
    with open(os.path.join(DATA_DIR, "input_log.txt"), "w") as f:
        f.write(f"Real key: {bytes(key).hex()}\n\n")
        f.write("Plaintexts (one per trace):\n")
        for i, pt in enumerate(plaintexts):
            f.write(f"{i:4d}  {bytes(pt).hex()}\n")


def plot_one_trace(traces):
    """Step 7: plot a single trace so we can see the AES round structure."""
    import matplotlib

    matplotlib.use("Agg")                   # draw plots to files, no window needed
    import matplotlib.pyplot as plt

    print("Step 7: saving one_trace.png")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    plt.figure(figsize=(10, 4), facecolor="white")
    plt.plot(traces[0], color="tab:blue", linewidth=0.6)
    plt.title("One power trace (AES-128 on XMEGA)")
    plt.xlabel("Sample number")
    plt.ylabel("Power (scaled ADC value)")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, "one_trace.png"), dpi=150)
    plt.close()


def parse_args(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Record AES-128 power traces from a "
                    "ChipWhisperer-Lite + XMEGA target.",
    )
    parser.add_argument("--traces", type=int, default=NUM_TRACES,
                        help=f"how many encryptions to record (default: {NUM_TRACES})")
    parser.add_argument("--samples", type=int, default=NUM_SAMPLES,
                        help=f"samples per trace (default: {NUM_SAMPLES})")
    parser.add_argument("--gain", type=float, default=GAIN,
                        help=f"amplifier gain in dB (default: {GAIN})")
    parser.add_argument("--firmware", default=FIRMWARE_PATH,
                        help="path to the compiled AES firmware .hex file")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    print_versions()
    scope, target = connect(gain=args.gain, samples=args.samples)
    try:
        flash_firmware(scope, args.firmware)
        traces, plaintexts, key = record_traces(scope, target)
        save_data(traces, plaintexts, key)
        plot_one_trace(traces)
    finally:
        print("Step 8: disconnecting")
        scope.dis()
        target.dis()
    print("Done. Now run: python attack.py")


if __name__ == "__main__":
    main()