"""Shared fixtures: synthetic traces that follow the tutorial's power model.

Power at sample ``leak + 5*b`` for key byte ``b`` is
``HW[Sbox[plaintext[b] ^ key[b]]]`` plus gaussian noise; every other sample
is exactly zero (flat).  A flat region is the classic pre-trigger baseline a
real scope records, and it is precisely what used to poison the correlation
(0/0 -> NaN).  ``flat_prefix`` just makes the flat region explicit.
"""

import numpy as np

from attack import sbox, HW


def make_traces(n=100, nsamp=520, leak=420, seed=0, noise=0.3, flat_prefix=0):
    rng = np.random.default_rng(seed)
    key = rng.integers(0, 256, 16, dtype=np.uint8)
    pts = rng.integers(0, 256, (n, 16), dtype=np.uint8)
    traces = np.zeros((n, nsamp))
    for i in range(n):
        for b in range(16):
            traces[i, leak + 5 * b] = HW[sbox[pts[i, b] ^ key[b]]] + rng.normal(0, noise)
    if flat_prefix:
        traces[:, :flat_prefix] = 0.0
    return traces, pts, key