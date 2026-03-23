"""
Benchmark: Group Signature Setup and Doctor Enrollment Cost

Measures:
    T_total(N) = T_setup + sum_{i=1..N} T_issue_i

For N in {10, 100, 1000, 10000}, the script:
1. runs setup() once
2. enrolls N doctors using join_issue_member_key()
3. records total elapsed time
4. repeats multiple runs
5. discards the highest and lowest run
6. averages the remaining runs
7. saves results to CSV

Output file:
- group_key_enrollment_results.csv
"""

from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path

from bbs04_python_core import setup, join_issue_member_key


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

ENROLLMENT_SIZES = [10, 100, 1000, 10000]
NUM_RUNS = 12
DROP_EXTREMES = True
OUTPUT_CSV = "group_key_enrollment_results.csv"


# ------------------------------------------------------------
# Benchmark helpers
# ------------------------------------------------------------

def benchmark_one_trial(num_doctors: int) -> float:
    """
    Run one benchmark trial and return total time (ms).
    """
    t0 = time.perf_counter()

    gpk, gmk = setup()

    for i in range(num_doctors):
        join_issue_member_key(
            gpk,
            gmk,
            member_id=f"doctor:{i:05d}"
        )

    t1 = time.perf_counter()

    total_ms = (t1 - t0) * 1000.0
    return total_ms


def trimmed_average(values: list[float]) -> float:
    if DROP_EXTREMES and len(values) >= 3:
        values = sorted(values)[1:-1]
    return statistics.mean(values)


def run_benchmark() -> list[dict]:
    results = []

    for n in ENROLLMENT_SIZES:
        trials = []

        print(f"\nBenchmarking N = {n} doctors")

        for run_idx in range(1, NUM_RUNS + 1):
            total_ms = benchmark_one_trial(n)
            trials.append(total_ms)

            print(f"  Run {run_idx:02d}: total={total_ms:.3f} ms")

        avg_total_ms = trimmed_average(trials)

        results.append({
            "num_doctors": n,
            "avg_total_ms": avg_total_ms
        })

        print(f"  Averaged total for N={n}: {avg_total_ms:.3f} ms")

    return results


# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

def save_csv(results: list[dict], filepath: str) -> None:
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["num_doctors", "avg_total_ms"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nSaved CSV results to: {Path(filepath).resolve()}")


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main() -> None:
    results = run_benchmark()
    save_csv(results, OUTPUT_CSV)

    print("\nFinal aggregated results:")
    for row in results:
        print(f"N={row['num_doctors']:>5} | total={row['avg_total_ms']:.3f} ms")


if __name__ == "__main__":
    main()
