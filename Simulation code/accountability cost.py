from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path
from typing import List

from bbs04_python_core import (
    setup as bbs04_setup,
    join_issue_member_key,
    sign,
    open as gs_open,
    serialize_elem,
)
from cl_bilinear_core import (
    setup as cl_setup,
    issuer_keygen,
)


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

ENROLLMENT_SIZES = [10, 100, 1000, 10000]
NUM_RUNS = 12
DROP_EXTREMES = True
OUTPUT_CSV = "accountability_cost_results.csv"


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def trimmed_average(values: List[float]) -> float:
    if not values:
        raise ValueError("values must not be empty")

    if DROP_EXTREMES and len(values) >= 3:
        values = sorted(values)[1:-1]

    return statistics.mean(values)


def build_registry_from_manager(gmk) -> dict[str, str]:
    """
    Build a hash-map registry:
        A_ser_hex -> member_id

    This simulates indexed identity recovery after signature opening.
    """
    registry = {}
    for a_hex, entry in gmk.registry_full.items():
        registry[a_hex] = entry["member_id"]
    return registry


def generate_ephemeral_cl_public_key_bytes() -> bytes:
    """
    Create an ephemeral CL issuer public key pk_hp^CL and serialize it.

    This models the actual object certified inside:
        auth_pres = (pk_hp^CL, sigma_grp)
    """
    # Number of attributes is not important for this accountability benchmark.
    # We only need a valid ephemeral CL issuer public key element.
    params = cl_setup(num_attributes=8)
    _, issuer_pk = issuer_keygen(params)
    return serialize_elem(issuer_pk.pk)


# ------------------------------------------------------------
# One benchmark trial
# ------------------------------------------------------------

def benchmark_one_trial(num_doctors: int) -> dict:
    """
    Measure accountability cost:
      1. opening cost
      2. identity recovery cost via Python dict lookup
      3. total accountability cost

    Excludes:
      - BBS04 setup
      - doctor enrollment
      - CL setup / ephemeral CL key generation
      - group-signature generation

    The signed message is the serialized ephemeral CL issuer public key,
    matching the protocol object used in auth_pres.
    """
    # --------------------------------------------------------
    # Setup and enrollment (not timed for this experiment)
    # --------------------------------------------------------
    gpk, gmk = bbs04_setup()

    member_keys = []
    for i in range(num_doctors):
        mkey = join_issue_member_key(
            gpk,
            gmk,
            member_id=f"doctor:{i:05d}",
        )
        member_keys.append(mkey)

    registry = build_registry_from_manager(gmk)

    # --------------------------------------------------------
    # Build the actual message covered by auth_pres:
    # serialized ephemeral CL issuer public key pk_hp^CL
    # --------------------------------------------------------
    message = generate_ephemeral_cl_public_key_bytes()

    # Pick one enrolled doctor to sign
    signer = member_keys[num_doctors // 2]

    sigma = sign(
        message=message,
        member_key=signer,
        group_public_key=gpk,
    )

    # --------------------------------------------------------
    # 1. Measure opening cost
    # --------------------------------------------------------
    t0 = time.perf_counter()
    opened = gs_open(
        message=message,
        signature=sigma,
        manager_key=gmk,
    )
    t1 = time.perf_counter()

    # --------------------------------------------------------
    # 2. Measure identity recovery cost
    # --------------------------------------------------------
    recovered_member_id = registry.get(opened["A_ser_hex"])
    t2 = time.perf_counter()

    if recovered_member_id is None:
        raise RuntimeError("identity recovery failed")

    open_ms = (t1 - t0) * 1000.0
    recovery_ms = (t2 - t1) * 1000.0
    total_ms = (t2 - t0) * 1000.0

    return {
        "num_doctors": num_doctors,
        "open_ms": open_ms,
        "identity_recovery_ms": recovery_ms,
        "accountability_total_ms": total_ms,
    }


# ------------------------------------------------------------
# Full benchmark
# ------------------------------------------------------------

def run_benchmark() -> List[dict]:
    results = []

    for n in ENROLLMENT_SIZES:
        trial_open = []
        trial_recovery = []
        trial_total = []

        print(f"\nBenchmarking accountability cost with {n} enrolled doctors")

        for run_idx in range(1, NUM_RUNS + 1):
            out = benchmark_one_trial(n)

            trial_open.append(out["open_ms"])
            trial_recovery.append(out["identity_recovery_ms"])
            trial_total.append(out["accountability_total_ms"])

            print(
                f"  Run {run_idx:02d}: "
                f"open={out['open_ms']:.3f} ms, "
                f"recovery={out['identity_recovery_ms']:.6f} ms, "
                f"total={out['accountability_total_ms']:.3f} ms"
            )

        avg_open = trimmed_average(trial_open)
        avg_recovery = trimmed_average(trial_recovery)
        avg_total = trimmed_average(trial_total)

        results.append({
            "num_doctors": n,
            "avg_open_ms": avg_open,
            "avg_identity_recovery_ms": avg_recovery,
            "avg_accountability_total_ms": avg_total,
        })

        print(
            f"  Averaged result ({n} doctors): "
            f"open={avg_open:.3f} ms, "
            f"recovery={avg_recovery:.6f} ms, "
            f"total={avg_total:.3f} ms"
        )

    return results


# ------------------------------------------------------------
# Save CSV
# ------------------------------------------------------------

def save_csv(results: List[dict], filepath: str) -> None:
    fieldnames = [
        "num_doctors",
        "avg_open_ms",
        "avg_identity_recovery_ms",
        "avg_accountability_total_ms",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
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
        print(
            f"N={row['num_doctors']:>5} | "
            f"open={row['avg_open_ms']:.3f} ms | "
            f"recovery={row['avg_identity_recovery_ms']:.6f} ms | "
            f"total={row['avg_accountability_total_ms']:.3f} ms"
        )


if __name__ == "__main__":
    main()