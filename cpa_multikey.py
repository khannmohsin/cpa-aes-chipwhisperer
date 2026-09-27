"""
cpa_multikey.py - Run the whole experiment for many different AES keys.

For each key we:
  1. Pick a fresh random 16-byte key.
  2. Capture TRACES_PER_KEY encryptions of random plaintexts under that key.
  3. Recover the key from the traces with CPA (the same code as attack.py).
  4. Check whether every byte matches.

At the end it prints how many of the keys were fully recovered and writes a
summary to results/multikey_summary.txt.

This reuses:
  - connect(), flash_firmware() and capture_pairs() from capture.py
  - recover_key() and confirms_device()       from attack.py
"""

import os
import numpy as np

from capture import connect, flash_firmware, capture_pairs   # board setup
from attack import recover_key, confirms_device               # the CPA + check

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
NUM_KEYS       = 20      # how many different keys to try
TRACES_PER_KEY = 100     # encryptions recorded per key (100 is plenty here)
NUM_SAMPLES    = 5000
GAIN           = 25

RESULTS_DIR = "results"


def main():
    from tqdm import tqdm

    scope, target = connect()
    results = []                      # (key_hex, recovered_hex, bytes_correct, confirmed)
    try:
        flash_firmware(scope)
        for k in tqdm(range(NUM_KEYS), desc="keys"):
            key = bytearray(np.random.randint(0, 256, 16, dtype=np.uint8).tolist())
            traces, plaintexts, cts = capture_pairs(scope, target, key, TRACES_PER_KEY)
            if len(traces) == 0:
                print(f"key {k}: no traces captured, skipping")
                continue
            recovered = recover_key(traces, plaintexts)
            correct = int(np.sum(recovered == np.array(key, dtype=np.uint8)))
            confirmed = confirms_device(recovered, plaintexts, cts)
            results.append((bytes(key).hex(), bytes(recovered).hex(), correct, confirmed))
    finally:
        print("disconnecting")
        scope.dis()
        target.dis()

    # ----- report -----
    os.makedirs(RESULTS_DIR, exist_ok=True)
    full = sum(1 for _, _, c, _ in results if c == 16)
    confirmed_n = sum(1 for _, _, _, ok in results if ok)
    lines = []
    lines.append(f"CPA on {len(results)} keys, {TRACES_PER_KEY} traces each\n")
    lines.append(f"Fully recovered:          {full} / {len(results)}\n")
    lines.append(f"Confirmed vs device output: {confirmed_n} / {len(results)}\n")
    lines.append("\n# key  real_key  recovered_key  bytes_correct  full?  confirmed?\n")
    for i, (real, rec, c, ok) in enumerate(results):
        lines.append(f"{i:3d}  {real}  {rec}  {c:2d}/16  "
                     f"{'yes' if c == 16 else 'NO':4s}  {'yes' if ok else 'NO'}\n")
    report = "".join(lines)
    with open(os.path.join(RESULTS_DIR, "multikey_summary.txt"), "w") as f:
        f.write(report)
    print("\n" + report)
    print("wrote results/multikey_summary.txt")


if __name__ == "__main__":
    main()