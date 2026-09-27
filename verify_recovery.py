"""
verify_recovery.py - Independently confirm that CPA really recovered the key.

Instead of comparing the recovered key against the key we told the board to use,
this does a check that trusts NEITHER our "real key" label NOR our CPA code:

  1. Capture (plaintext, ciphertext) pairs from the chip. The ciphertext is what
     the real hardware actually produced - we never assume we know the key.
  2. Run CPA to recover the key from the power traces.
  3. Encrypt the SAME plaintexts with the recovered key using a completely
     separate AES library (PyCryptodome).
  4. If those ciphertexts equal the chip's ciphertexts for every plaintext, the
     recovered key must be the exact key inside the device. That is proof by
     matching the device's real output, not by trusting our own bookkeeping.

Run several keys to be convinced it is not a fluke.
"""

import numpy as np

from capture import connect, flash_firmware, capture_pairs
from attack import recover_key, confirms_device

NUM_KEYS       = 3       # how many keys to check this way
TRACES_PER_KEY = 100


def main():
    scope, target = connect()
    try:
        flash_firmware(scope)
        all_ok = True
        for k in range(NUM_KEYS):
            key = bytearray(np.random.randint(0, 256, 16, dtype=np.uint8).tolist())
            traces, plaintexts, cts = capture_pairs(scope, target, key, TRACES_PER_KEY)
            recovered = recover_key(traces, plaintexts)

            matches_device = confirms_device(recovered, plaintexts, cts)
            # We also print the true key just so you can eyeball it, but the proof
            # above does not depend on knowing it.
            print(f"\nkey {k}")
            print(f"  recovered:              {bytes(recovered).hex()}")
            print(f"  (real key, for eyeball) {bytes(key).hex()}")
            print(f"  reproduces device ciphertext for all {len(cts)} plaintexts: "
                  f"{'YES' if matches_device else 'no'}")
            all_ok = all_ok and matches_device
        print("\nOverall:", "all keys independently confirmed" if all_ok
              else "at least one key did NOT confirm")
    finally:
        scope.dis()
        target.dis()


if __name__ == "__main__":
    main()