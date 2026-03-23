from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Set

from cl_bilinear_core import (
    CLPublicParameters,
    CLIssuerPublicKey,
    CLCredential,
    _bn,
    _mod,
    _rand_scalar_nonzero,
    point_mul,
    hash_to_scalar,
    serialize_elem,
    setup,
    issuer_keygen,
    user_keygen,
    generate_issue_request_proof,
    issue_credential,
    verify_credential_signature,
)


# ============================================================
# Data class
# ============================================================

@dataclass
class CLPresentationProof:
    """
    Standard CL presentation proof for selective disclosure.

    Fields:
      - sigma_prime: randomized credential signature
      - c: Fiat-Shamir challenge
      - rrand_tilde: response for signature randomizer
      - skuser_tilde: response for user secret key
      - hidden_attr_responses: responses for hidden attributes, keyed by index
      - disclosed_attributes: disclosed attributes, keyed by index
      - hidden_indices: sorted hidden indices
      - disclosed_indices: sorted disclosed indices
      - nonce: verifier nonce
    """
    sigma_prime: Any
    c: Any
    rrand_tilde: Any
    skuser_tilde: Any
    hidden_attr_responses: Dict[int, Any]
    disclosed_attributes: Dict[int, Any]
    hidden_indices: List[int]
    disclosed_indices: List[int]
    nonce: bytes


# ============================================================
# Helpers
# ============================================================

def _validate_partition(num_attributes: int, disclosed_indices: Sequence[int]) -> tuple[List[int], List[int]]:
    disclosed_set: Set[int] = set(disclosed_indices)

    if any(i < 0 or i >= num_attributes for i in disclosed_set):
        raise ValueError("disclosed index out of range")

    disclosed_sorted = sorted(disclosed_set)
    hidden_sorted = sorted(set(range(num_attributes)) - disclosed_set)

    if len(disclosed_sorted) + len(hidden_sorted) != num_attributes:
        raise ValueError("invalid partition of attributes")

    return disclosed_sorted, hidden_sorted


def _sum_disclosed_commitment(
    params: CLPublicParameters,
    disclosed_attributes: Dict[int, Any],
) -> Any:
    """
    H_disclosed = sum_{i in M_disclosed} m_i * H_i
    """
    q = params.order
    H_disclosed = point_mul(params.g1, 0, q)

    for idx, value in disclosed_attributes.items():
        H_disclosed = H_disclosed + point_mul(params.H_attrs[idx], _mod(value, q), q)

    return H_disclosed


def _sum_hidden_response_commitment(
    params: CLPublicParameters,
    hidden_attr_responses: Dict[int, Any],
) -> Any:
    """
    H_tilde_hidden = sum_{i in M_hidden} m_tilde_i * H_i
    """
    q = params.order
    H_hidden_tilde = point_mul(params.g1, 0, q)

    for idx, m_tilde in hidden_attr_responses.items():
        H_hidden_tilde = H_hidden_tilde + point_mul(params.H_attrs[idx], _mod(m_tilde, q), q)

    return H_hidden_tilde


# ============================================================
# Proof generation
# ============================================================

def generate_presentation_proof(
    params: CLPublicParameters,
    issuer_public_key: CLIssuerPublicKey,
    credential: CLCredential,
    user_secret_key: Any,
    disclosed_indices: Sequence[int],
    nonce: bytes,
) -> CLPresentationProof:
    """
    Generate standard CL hidden-attribute proof with selective disclosure.

    Proves possession of a valid credential while revealing only selected
    disclosed attributes.
    """
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("nonce must be bytes")

    q = params.order
    num_attributes = len(params.H_attrs)

    disclosed_sorted, hidden_sorted = _validate_partition(num_attributes, disclosed_indices)
    attrs_bn = [_mod(m, q) for m in credential.attributes]

    # Build disclosed attribute dictionary
    disclosed_attributes: Dict[int, Any] = {
        i: attrs_bn[i] for i in disclosed_sorted
    }

    # ------------------------------------------------------------
    # Step 1. Randomize signature: sigma' = sigma + rrand * g1
    # ------------------------------------------------------------
    rrand = q.random()
    sigma_prime = credential.sigma + point_mul(params.g1, rrand, q)

    # ------------------------------------------------------------
    # Step 2. Blind the witnesses
    # ------------------------------------------------------------
    rrand_blind = q.random()
    skuser_blind = q.random()

    hidden_attr_blinds: Dict[int, Any] = {}
    for i in hidden_sorted:
        hidden_attr_blinds[i] = q.random()

    # ------------------------------------------------------------
    # Step 3. H'_hidden = sk'_user * g1 + sum_{i in hidden} m'_i * H_i
    # ------------------------------------------------------------
    H_hidden_blind = point_mul(params.g1, skuser_blind, q)
    for i in hidden_sorted:
        H_hidden_blind = H_hidden_blind + point_mul(params.H_attrs[i], hidden_attr_blinds[i], q)

    # ------------------------------------------------------------
    # Step 4. A = e(g1,g2)^{r'_rand} * e(H'_hidden, pk_issuer)
    # ------------------------------------------------------------
    e_g1_g2 = params.group.pair(params.g1, params.g2)
    A = (e_g1_g2 ** _bn(rrand_blind)) * params.group.pair(H_hidden_blind, issuer_public_key.pk)

    # ------------------------------------------------------------
    # Step 5. Fiat-Shamir challenge
    # ------------------------------------------------------------
    c = hash_to_scalar(q, sigma_prime, A, nonce)

    # ------------------------------------------------------------
    # Step 6. Responses
    # ------------------------------------------------------------
    rrand_tilde = (rrand_blind + c * _bn(rrand)).mod(q)
    skuser_tilde = (skuser_blind + c * _bn(user_secret_key.y)).mod(q)

    hidden_attr_responses: Dict[int, Any] = {}
    for i in hidden_sorted:
        hidden_attr_responses[i] = (hidden_attr_blinds[i] + c * attrs_bn[i]).mod(q)

    return CLPresentationProof(
        sigma_prime=sigma_prime,
        c=c,
        rrand_tilde=rrand_tilde,
        skuser_tilde=skuser_tilde,
        hidden_attr_responses=hidden_attr_responses,
        disclosed_attributes=disclosed_attributes,
        hidden_indices=hidden_sorted,
        disclosed_indices=disclosed_sorted,
        nonce=bytes(nonce),
    )


# ============================================================
# Proof verification
# ============================================================

def verify_presentation_proof(
    params: CLPublicParameters,
    issuer_public_key: CLIssuerPublicKey,
    proof: CLPresentationProof,
) -> bool:
    """
    Verify standard CL hidden-attribute proof with selective disclosure.
    """
    q = params.order
    num_attributes = len(params.H_attrs)

    # Basic sanity checks
    disclosed_sorted, hidden_sorted = _validate_partition(num_attributes, proof.disclosed_indices)

    if disclosed_sorted != proof.disclosed_indices:
        return False
    if hidden_sorted != proof.hidden_indices:
        return False
    if set(proof.hidden_attr_responses.keys()) != set(hidden_sorted):
        return False
    if set(proof.disclosed_attributes.keys()) != set(disclosed_sorted):
        return False

    # ------------------------------------------------------------
    # Step 1. Compute H_disclosed
    # ------------------------------------------------------------
    H_disclosed = _sum_disclosed_commitment(params, proof.disclosed_attributes)

    # ------------------------------------------------------------
    # Step 2. Compute H_tilde_hidden
    # ------------------------------------------------------------
    H_hidden_tilde = _sum_hidden_response_commitment(params, proof.hidden_attr_responses)

    # ------------------------------------------------------------
    # Step 3. H''_hidden = sk_tilde * g1 + H_tilde_hidden
    # ------------------------------------------------------------
    H_hidden_reconstructed = point_mul(params.g1, proof.skuser_tilde, q) + H_hidden_tilde

    # ------------------------------------------------------------
    # Step 4. Reconstruct A'
    #
    # ProofRelation = e(sigma', g2) / e(H_disclosed, pk_issuer)
    # A' = ProofRelation^{-c} * e(g1,g2)^{rrand_tilde} * e(H''_hidden, pk_issuer)
    # ------------------------------------------------------------
    e_sigma_prime_g2 = params.group.pair(proof.sigma_prime, params.g2)
    e_H_disclosed_pk = params.group.pair(H_disclosed, issuer_public_key.pk)
    e_g1_g2 = params.group.pair(params.g1, params.g2)
    e_Hhidden_pk = params.group.pair(H_hidden_reconstructed, issuer_public_key.pk)

    proof_relation = e_sigma_prime_g2 * (e_H_disclosed_pk ** (-_bn(1)))
    A_reconstructed = (proof_relation ** (-_bn(proof.c))) * (e_g1_g2 ** _bn(proof.rrand_tilde)) * e_Hhidden_pk

    # ------------------------------------------------------------
    # Step 5. Recompute challenge
    # ------------------------------------------------------------
    c_check = hash_to_scalar(q, proof.sigma_prime, A_reconstructed, proof.nonce)

    return c_check == proof.c


# ============================================================
# Optional smoke test
# ============================================================

if __name__ == "__main__":
    # Example: 4 prescription attributes
    # 0: prescription_id
    # 1: medication_id
    # 2: dosage
    # 3: issue_date

    params = setup(num_attributes=4)
    isk, ipk = issuer_keygen(params)
    usk, upk = user_keygen(params)

    attrs = [
        1001,     # prescription identifier
        55,       # medication identifier
        2,        # dosage
        20260317, # issue date
    ]

    # -------------------------------
    # Issue credential first
    # -------------------------------
    req = generate_issue_request_proof(
        params=params,
        user_secret_key=usk,
        attributes=attrs,
        nonce=b"issue-request-nonce",
    )

    cred = issue_credential(
        params=params,
        issuer_secret_key=isk,
        request=req,
        attributes=attrs,
        user_public_key=upk,
        verify_request_first=True,
    )

    print("credential signature valid?", verify_credential_signature(params, ipk, cred))

    # -------------------------------
    # Presentation proof:
    # disclose only medication_id
    # -------------------------------
    disclosed_indices = [1]
    proof = generate_presentation_proof(
        params=params,
        issuer_public_key=ipk,
        credential=cred,
        user_secret_key=usk,
        disclosed_indices=disclosed_indices,
        nonce=b"presentation-nonce",
    )

    ok = verify_presentation_proof(
        params=params,
        issuer_public_key=ipk,
        proof=proof,
    )

    print("presentation proof valid?", ok)