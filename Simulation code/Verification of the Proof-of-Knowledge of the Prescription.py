from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path
from typing import Any, Dict, List

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


TOTAL_ATTRIBUTES = 8
NUM_RUNS = 12
DROP_EXTREMES = True
OUTPUT_CSV = "prescription_pok_verification_results.csv"

DISCLOSED_COUNTS = [1, 2, 3, 4]
EXPIRY_INDEX = 3
DISCLOSURE_CANDIDATES = [4, 5, 0, 1]


def build_prescription_attributes() -> List[int]:
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
    return {
        "proof": proof,
        "auth_pres": auth_pres,
    }


def benchmark_one_trial(
    params,
    issuer_pk,
    user_pk,
    presentation_package,
    group_public_key,
    G_range,
    H_range,
) -> Dict[str, float]:
    t0 = time.perf_counter()
    ok_proof = verify_presentation_proof_with_range(
        params=params,
        issuer_public_key=issuer_pk,
        patient_public_key=user_pk,
        proof=presentation_package["proof"],
        G_range=G_range,
        H_range=H_range,
    )
    t1 = time.perf_counter()

    if not ok_proof:
        raise RuntimeError("presentation proof verification failed")

    auth_pres = presentation_package["auth_pres"]
    ok_auth = bbs04_verify(
        auth_pres["pk_hp_cl_bytes"],
        auth_pres["sigma_grp"],
        group_public_key,
    )
    t2 = time.perf_counter()

    if not ok_auth:
        raise RuntimeError("auth_pres verification failed")

    proof_verification_ms = (t1 - t0) * 1000.0
    auth_pres_verification_ms = (t2 - t1) * 1000.0
    combined_verification_ms = (t2 - t0) * 1000.0

    return {
        "proof_verification_ms": proof_verification_ms,
        "auth_pres_verification_ms": auth_pres_verification_ms,
        "combined_verification_ms": combined_verification_ms,
    }


def run_benchmark() -> List[Dict[str, float]]:
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

    req = generate_issue_request_proof(
        params=params,
        user_secret_key=user_sk,
        attributes=attrs,
        nonce=b"issue-request-verification-benchmark",
    )

    credential = issue_credential(
        params=params,
        issuer_secret_key=issuer_sk,
        request=req,
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
        raise RuntimeError("initial auth_pres sanity verification failed")

    q = params.order
    G_range = point_mul(params.g1, q.random(), q)
    H_range = point_mul(params.g1, q.random(), q)

    T = 140
    B = 15

    for disclose_count in DISCLOSED_COUNTS:
        disclosed_indices = get_disclosed_indices(disclose_count)

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
            nonce=f"presentation-range-{disclose_count}".encode("utf-8"),
            G_range=G_range,
            H_range=H_range,
        )

        presentation_package = build_presentation_package(
            proof=proof,
            auth_pres=auth_pres,
        )

        ok_proof = verify_presentation_proof_with_range(
            params=params,
            issuer_public_key=issuer_pk,
            patient_public_key=user_pk,
            proof=proof,
            G_range=G_range,
            H_range=H_range,
        )
        if not ok_proof:
            raise RuntimeError("initial proof sanity verification failed")

        trial_total: List[float] = []

        print(
            f"\nBenchmarking combined verification: "
            f"disclose {disclose_count}, hide {TOTAL_ATTRIBUTES - disclose_count}"
        )

        for run_idx in range(1, NUM_RUNS + 1):
            out = benchmark_one_trial(
                params=params,
                issuer_pk=issuer_pk,
                user_pk=user_pk,
                presentation_package=presentation_package,
                group_public_key=group_public_key,
                G_range=G_range,
                H_range=H_range,
            )

            trial_total.append(out["combined_verification_ms"])

            print(
                f"  Run {run_idx:02d}: "
                f"combined={out['combined_verification_ms']:.3f} ms"
            )

        avg_total = trimmed_average(trial_total)

        results.append({
            "disclosed_count": disclose_count,
            "hidden_count": TOTAL_ATTRIBUTES - disclose_count,
            "avg_combined_verification_ms": avg_total,
        })

        print(
            f"  Averaged result: "
            f"disclose={disclose_count}, "
            f"hide={TOTAL_ATTRIBUTES - disclose_count}, "
            f"combined={avg_total:.3f} ms"
        )

    return results


def save_csv(results: List[Dict[str, float]], filepath: str) -> None:
    """
    Save only the fields that actually vary in this experiment.
    total_attributes is fixed (= 8), so it is intentionally omitted.
    """
    fieldnames = [
        "disclosed_count",
        "hidden_count",
        "avg_combined_verification_ms",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in results:
            writer.writerow({
                "disclosed_count": row["disclosed_count"],
                "hidden_count": row["hidden_count"],
                "avg_combined_verification_ms": row["avg_combined_verification_ms"],
            })

    print(f"\nSaved CSV results to: {Path(filepath).resolve()}")


def main() -> None:
    results = run_benchmark()
    save_csv(results, OUTPUT_CSV)

    print("\nFinal aggregated results:")
    for row in results:
        print(
            f"disclose={row['disclosed_count']}, "
            f"hide={row['hidden_count']} | "
            f"combined={row['avg_combined_verification_ms']:.3f} ms"
        )


if __name__ == "__main__":
    main()