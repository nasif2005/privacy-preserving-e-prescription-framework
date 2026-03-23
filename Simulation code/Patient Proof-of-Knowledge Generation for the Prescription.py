from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from cl_bilinear_core import (
    setup as cl_setup,
    issuer_keygen,
    user_keygen,
    generate_issue_request_proof,
    issue_credential,
    point_mul,
)
from cl_bilinear_pok_range import (
    generate_presentation_proof_with_range,
    verify_presentation_proof_with_range,
)
from bbs04_python_core import (
    setup as bbs04_setup,
    join_issue_member_key,
    sign as bbs04_sign,
    verify as bbs04_verify,
    serialize_elem,
)


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

TOTAL_ATTRIBUTES = 8
NUM_RUNS = 12
DROP_EXTREMES = True
OUTPUT_CSV = "prescription_pok_generation_results.csv"

# Scenario A disclosure settings for total attributes = 8
# The actual varying parameter is disclosure configuration.
DISCLOSED_COUNTS = [1, 2, 3, 4]


# ------------------------------------------------------------
# Prescription structure for total_attributes = 8
# ------------------------------------------------------------
# 0. prescription_id
# 1. healthcare_professional_id
# 2. patient_id
# 3. expiry_date
# 4. medication_id_1
# 5. dosage_1
# 6. medication_id_2
# 7. dosage_2
#
# Important:
# - expiry_date (index 3) is always hidden
# - disclosed set grows, but expiry_date remains hidden in all cases
# ------------------------------------------------------------

EXPIRY_INDEX = 3

# These are the attributes we are willing to disclose, in order.
# We intentionally keep expiry_date hidden in all cases.
DISCLOSURE_CANDIDATES = [4, 5, 0, 1]  # med1_id, dosage1, prescription_id, healthcare_professional_id


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def build_prescription_attributes() -> List[int]:
    """
    Build a fixed 8-attribute prescription:
      header + 2 medication entries
    """
    return [
        100008,    # prescription_id
        5000,      # healthcare_professional_id
        900000,    # patient_id
        150,       # expiry_date
        200,       # medication_id_1
        1,         # dosage_1
        201,       # medication_id_2
        2,         # dosage_2
    ]


def get_disclosed_indices(disclose_count: int) -> List[int]:
    """
    Return disclosed indices for Scenario A.
    Expiry index is never disclosed.
    """
    if disclose_count < 1 or disclose_count > len(DISCLOSURE_CANDIDATES):
        raise ValueError("invalid disclose_count")
    return DISCLOSURE_CANDIDATES[:disclose_count]


def trimmed_average(values: List[float]) -> float:
    if not values:
        raise ValueError("values must not be empty")

    working = list(values)
    if DROP_EXTREMES and len(working) >= 3:
        working = sorted(working)[1:-1]

    return statistics.mean(working)


def generate_auth_pres(
    issuer_public_key: Any,
    doctor_member_key: Any,
    group_public_key: Any,
) -> Dict[str, Any]:
    """
    Authorization certificate:
        auth_pres = (pk_hp^CL, sigma_grp)

    where sigma_grp is a BBS04 group signature over the serialized
    ephemeral CL issuer public key.
    """
    pk_hp_cl_bytes = serialize_elem(issuer_public_key.pk)
    sigma_grp = bbs04_sign(pk_hp_cl_bytes, doctor_member_key, group_public_key)

    return {
        "pk_hp_cl": issuer_public_key.pk,
        "pk_hp_cl_bytes": pk_hp_cl_bytes,
        "sigma_grp": sigma_grp,
    }


def build_presentation_package(
    proof: Any,
    auth_pres: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Package submitted by the patient during prescription presentation.
    """
    return {
        "proof": proof,
        "auth_pres": auth_pres,
    }


# ------------------------------------------------------------
# One benchmark trial
# ------------------------------------------------------------

def benchmark_one_trial(
    params,
    issuer_pk,
    credential,
    user_sk,
    user_pk,
    disclosed_indices: Sequence[int],
    G_range,
    H_range,
    T: int,
    B: int,
    auth_pres: Dict[str, Any],
) -> Dict[str, float]:
    """
    Measure only proof generation time for the modified CL PoK with range validity.

    Important:
      - auth_pres is INCLUDED in the returned presentation package
      - auth_pres generation is NOT timed here, because it belongs to the
        prescription issuance phase, not the patient proof-generation phase
    """
    nonce = f"presentation-range-{len(disclosed_indices)}".encode("utf-8")

    t0 = time.perf_counter()
    proof = generate_presentation_proof_with_range(
        params=params,
        issuer_public_key=issuer_pk,
        patient_public_key=user_pk,
        credential=credential,
        user_secret_key=user_sk,
        disclosed_indices=disclosed_indices,
        expiry_index=EXPIRY_INDEX,
        T=T,
        B=B,
        nonce=nonce,
        G_range=G_range,
        H_range=H_range,
    )
    presentation_package = build_presentation_package(
        proof=proof,
        auth_pres=auth_pres,
    )
    t1 = time.perf_counter()

    ok_proof = verify_presentation_proof_with_range(
        params=params,
        issuer_public_key=issuer_pk,
        patient_public_key=user_pk,
        proof=presentation_package["proof"],
        G_range=G_range,
        H_range=H_range,
    )
    if not ok_proof:
        raise RuntimeError("generated presentation proof failed verification")

    generation_ms = (t1 - t0) * 1000.0

    return {
        "disclosed_count": len(disclosed_indices),
        "hidden_count": TOTAL_ATTRIBUTES - len(disclosed_indices),
        "proof_generation_ms": generation_ms,
    }


# ------------------------------------------------------------
# Full benchmark
# ------------------------------------------------------------

def run_benchmark() -> List[Dict[str, float]]:
    """
    For each disclosure setting:
      - disclose 1, hide 7
      - disclose 2, hide 6
      - disclose 3, hide 5
      - disclose 4, hide 4

    Measure patient proof generation time.

    The patient's submitted presentation package contains:
      - the unified CL/range proof
      - auth_pres = (pk_hp^CL, sigma_grp)

    but only the proof generation cost is timed in this script.
    """
    results: List[Dict[str, float]] = []

    params = cl_setup(num_attributes=TOTAL_ATTRIBUTES)
    issuer_sk, issuer_pk = issuer_keygen(params)
    user_sk, user_pk = user_keygen(params)

    attrs = build_prescription_attributes()

    group_public_key, manager_key = bbs04_setup()
    doctor_member_key = join_issue_member_key(
        group_public_key,
        manager_key,
        member_id="doctor:lic-ON-48291",
    )

    issue_req = generate_issue_request_proof(
        params=params,
        user_secret_key=user_sk,
        attributes=attrs,
        nonce=b"issue-request-scenario-A",
    )

    credential = issue_credential(
        params=params,
        issuer_secret_key=issuer_sk,
        request=issue_req,
        attributes=attrs,
        user_public_key=user_pk,
        verify_request_first=True,
    )

    auth_pres = generate_auth_pres(
        issuer_public_key=issuer_pk,
        doctor_member_key=doctor_member_key,
        group_public_key=group_public_key,
    )

    ok_auth = bbs04_verify(
        auth_pres["pk_hp_cl_bytes"],
        auth_pres["sigma_grp"],
        group_public_key,
    )
    if not ok_auth:
        raise RuntimeError("auth_pres verification failed")

    q = params.order
    G_range = point_mul(params.g1, q.random(), q)
    H_range = point_mul(params.g1, q.random(), q)

    T = 140
    B = 15

    for disclose_count in DISCLOSED_COUNTS:
        disclosed_indices = get_disclosed_indices(disclose_count)

        trial_gen: List[float] = []

        print(
            f"\nBenchmarking proof generation: "
            f"disclose {disclose_count}, hide {TOTAL_ATTRIBUTES - disclose_count}"
        )

        for run_idx in range(1, NUM_RUNS + 1):
            out = benchmark_one_trial(
                params=params,
                issuer_pk=issuer_pk,
                credential=credential,
                user_sk=user_sk,
                user_pk=user_pk,
                disclosed_indices=disclosed_indices,
                G_range=G_range,
                H_range=H_range,
                T=T,
                B=B,
                auth_pres=auth_pres,
            )

            trial_gen.append(out["proof_generation_ms"])

            print(f"  Run {run_idx:02d}: gen={out['proof_generation_ms']:.3f} ms")

        avg_gen = trimmed_average(trial_gen)

        results.append({
            "disclosed_count": disclose_count,
            "hidden_count": TOTAL_ATTRIBUTES - disclose_count,
            "avg_proof_generation_ms": avg_gen,
        })

        print(
            f"  Averaged result: "
            f"disclose={disclose_count}, "
            f"hide={TOTAL_ATTRIBUTES - disclose_count}, "
            f"gen={avg_gen:.3f} ms"
        )

    return results


# ------------------------------------------------------------
# Save CSV
# ------------------------------------------------------------

def save_csv(results: List[Dict[str, float]], filepath: str) -> None:
    """
    Save only the fields that actually vary in this experiment.
    total_attributes is fixed (= 8), so it is intentionally omitted.
    """
    fieldnames = [
        "disclosed_count",
        "hidden_count",
        "avg_proof_generation_ms",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in results:
            writer.writerow({
                "disclosed_count": row["disclosed_count"],
                "hidden_count": row["hidden_count"],
                "avg_proof_generation_ms": row["avg_proof_generation_ms"],
            })

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
            f"disclose={row['disclosed_count']}, "
            f"hide={row['hidden_count']} | "
            f"gen={row['avg_proof_generation_ms']:.3f} ms"
        )


if __name__ == "__main__":
    main()