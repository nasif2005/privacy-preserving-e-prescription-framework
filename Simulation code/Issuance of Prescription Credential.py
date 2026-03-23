from __future__ import annotations

import csv
import statistics
import time
from pathlib import Path
from typing import List

from cl_bilinear_core import (
    setup as cl_setup,
    issuer_keygen,
    user_keygen,
    generate_issue_request_proof,
    verify_issue_request_proof,
    issue_credential,
)

from bbs04_python_core import (
    setup as bbs04_setup,
    join_issue_member_key,
    sign as bbs04_sign,
    serialize_elem,
)


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

ATTRIBUTE_SIZES = [4, 6, 8, 10, 12]
NUM_RUNS = 12
DROP_EXTREMES = True
OUTPUT_CSV = "prescription_issuance_results.csv"


# ------------------------------------------------------------
# Prescription attribute builder
# ------------------------------------------------------------

def build_prescription_attributes(total_attributes: int) -> List[int]:
    """
    Prescription structure:

      Header:
        0. prescription_id
        1. healthcare_professional_id
        2. patient_id
        3. expiry_date

      Medication entries:
        medication_id_j
        dosage_j

    Total attribute count must be 4 + 2k.
    """
    if total_attributes < 4 or (total_attributes - 4) % 2 != 0:
        raise ValueError("total_attributes must satisfy 4 + 2k")

    num_medications = (total_attributes - 4) // 2

    attrs: List[int] = [
        100000 + total_attributes,  # prescription_id
        5000,                       # healthcare_professional_id
        900000,                     # patient_id
        20260430,                   # expiry_date
    ]

    for j in range(num_medications):
        attrs.append(200 + j)       # medication_id_j
        attrs.append(1 + j)         # dosage_j

    return attrs


# ------------------------------------------------------------
# Statistics helper
# ------------------------------------------------------------

def trimmed_average(values: List[float]) -> float:
    if not values:
        raise ValueError("values must not be empty")

    if DROP_EXTREMES and len(values) >= 3:
        values = sorted(values)[1:-1]

    return statistics.mean(values)


# ------------------------------------------------------------
# Helper: build auth_pres
# ------------------------------------------------------------

def generate_auth_pres(issuer_public_key, doctor_member_key, group_public_key):
    """
    Generate the authorization certificate:

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


# ------------------------------------------------------------
# One benchmark trial
# ------------------------------------------------------------

def benchmark_one_trial(
    params,
    issuer_sk,
    issuer_pk,
    user_sk,
    user_pk,
    doctor_member_key,
    group_public_key,
    total_attributes: int,
) -> dict:
    """
    Measure combined prescription issuance cost for one trial.

    Includes:
      - issuance request proof generation
      - issuance request proof verification
      - CL credential signature generation
      - auth_pres generation via BBS04 group signature on pk_hp^CL

    Excludes:
      - CL global setup
      - CL issuer key generation
      - CL user key generation
      - BBS04 setup
      - BBS04 doctor enrollment
    """
    attrs = build_prescription_attributes(total_attributes)
    nonce = f"issue-request-{total_attributes}".encode("utf-8")

    # 1. Issuance request proof generation
    t0 = time.perf_counter()
    req = generate_issue_request_proof(
        params=params,
        user_secret_key=user_sk,
        attributes=attrs,
        nonce=nonce,
    )
    t1 = time.perf_counter()

    # 2. Issuance request proof verification
    ok_req = verify_issue_request_proof(params, req)
    t2 = time.perf_counter()

    if not ok_req:
        raise RuntimeError("issuance request proof verification failed")

    # 3. Credential signature generation
    cred = issue_credential(
        params=params,
        issuer_secret_key=issuer_sk,
        request=req,
        attributes=attrs,
        user_public_key=user_pk,
        verify_request_first=False,  # already measured verification above
    )
    t3 = time.perf_counter()

    # 4. Authorization certificate generation: auth_pres
    auth_pres = generate_auth_pres(
        issuer_public_key=issuer_pk,
        doctor_member_key=doctor_member_key,
        group_public_key=group_public_key,
    )
    t4 = time.perf_counter()

    proof_generation_ms = (t1 - t0) * 1000.0
    proof_verification_ms = (t2 - t1) * 1000.0
    cl_signature_generation_ms = (t3 - t2) * 1000.0
    auth_pres_generation_ms = (t4 - t3) * 1000.0
    combined_issuance_total_ms = (t4 - t0) * 1000.0

    _ = cred
    _ = auth_pres

    return {
        "total_attributes": total_attributes,
        "proof_generation_ms": proof_generation_ms,
        "proof_verification_ms": proof_verification_ms,
        "cl_signature_generation_ms": cl_signature_generation_ms,
        "auth_pres_generation_ms": auth_pres_generation_ms,
        "combined_issuance_total_ms": combined_issuance_total_ms,
    }


# ------------------------------------------------------------
# Full benchmark
# ------------------------------------------------------------

def run_benchmark() -> List[dict]:
    results = []

    # --------------------------------------------------------
    # BBS04 setup and doctor enrollment are outside the
    # per-prescription issuance benchmark.
    # --------------------------------------------------------
    group_public_key, manager_key = bbs04_setup()
    doctor_member_key = join_issue_member_key(
        group_public_key,
        manager_key,
        member_id="doctor:lic-ON-48291",
    )

    for attr_count in ATTRIBUTE_SIZES:
        # CL setup once per attribute size, not per trial
        params = cl_setup(num_attributes=attr_count)
        issuer_sk, issuer_pk = issuer_keygen(params)
        user_sk, user_pk = user_keygen(params)

        trial_total = []

        print(f"\nBenchmarking combined prescription issuance with {attr_count} attributes")

        for run_idx in range(1, NUM_RUNS + 1):
            out = benchmark_one_trial(
                params=params,
                issuer_sk=issuer_sk,
                issuer_pk=issuer_pk,
                user_sk=user_sk,
                user_pk=user_pk,
                doctor_member_key=doctor_member_key,
                group_public_key=group_public_key,
                total_attributes=attr_count,
            )

            trial_total.append(out["combined_issuance_total_ms"])

            print(
                f"  Run {run_idx:02d}: "
                f"combined={out['combined_issuance_total_ms']:.3f} ms"
            )

        avg_total = trimmed_average(trial_total)

        results.append({
            "total_attributes": attr_count,
            "avg_combined_issuance_total_ms": avg_total,
        })

        print(
            f"  Averaged result ({attr_count} attrs): "
            f"combined={avg_total:.3f} ms"
        )

    return results


# ------------------------------------------------------------
# Save CSV
# ------------------------------------------------------------

def save_csv(results: List[dict], filepath: str) -> None:
    fieldnames = [
        "total_attributes",
        "avg_combined_issuance_total_ms",
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
            f"attrs={row['total_attributes']:>2} | "
            f"combined={row['avg_combined_issuance_total_ms']:.3f} ms"
        )


if __name__ == "__main__":
    main()