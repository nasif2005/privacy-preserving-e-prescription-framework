from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Set

from cl_bilinear_core import (
    CLPublicParameters,
    CLIssuerPublicKey,
    CLUserPublicKey,
    CLCredential,
    _bn,
    _mod,
    point_mul,
    hash_to_scalar,
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
class CLRangePresentationProof:
    sigma_prime: Any
    c: Any
    rrand_tilde: Any
    skuser_tilde: Any
    hidden_attr_responses: Dict[int, Any]
    disclosed_attributes: Dict[int, Any]
    hidden_indices: List[int]
    disclosed_indices: List[int]

    expiry_index: int
    C_exp: Any
    r_exp_tilde: Any
    C_bits: List[Any]
    s_sum: Any
    sigma_or: List[tuple[Any, Any, Any, Any]]

    T: int
    B: int
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
    q = params.order
    H_disclosed = point_mul(params.g1, 0, q)

    for idx, value in disclosed_attributes.items():
        H_disclosed = H_disclosed + point_mul(params.H_attrs[idx], _mod(value, q), q)

    return H_disclosed


def _sum_hidden_response_commitment(
    params: CLPublicParameters,
    hidden_attr_responses: Dict[int, Any],
) -> Any:
    q = params.order
    H_hidden_tilde = point_mul(params.g1, 0, q)

    for idx, m_tilde in hidden_attr_responses.items():
        H_hidden_tilde = H_hidden_tilde + point_mul(params.H_attrs[idx], _mod(m_tilde, q), q)

    return H_hidden_tilde


def _ceil_log2(x: int) -> int:
    if x <= 0:
        raise ValueError("x must be positive")
    return math.ceil(math.log2(x))


def _bit_decompose(delta: int, ell: int) -> List[int]:
    if delta < 0:
        raise ValueError("delta must be non-negative")
    return [(delta >> i) & 1 for i in range(ell)]


def _hash_range_transcript(
    q: Any,
    sigma_prime: Any,
    A_commitment: Any,
    C_exp: Any,
    R_exp: Any,
    C_bits: List[Any],
    C_sum_commitment: Any,
    sigma_or_reconstructed: List[Any],
    issuer_pk: Any,
    patient_pk: Any,
    T: int,
    B: int,
    nonce: bytes,
) -> Any:
    parts: List[Any] = [sigma_prime, A_commitment, C_exp, R_exp]
    parts.extend(C_bits)
    parts.append(C_sum_commitment)
    parts.extend(sigma_or_reconstructed)
    parts.append(issuer_pk)
    parts.append(patient_pk)
    parts.append(T)
    parts.append(B)
    parts.append(nonce)
    return hash_to_scalar(q, *parts)


# ============================================================
# Proof generation
# ============================================================

def generate_presentation_proof_with_range(
    params: CLPublicParameters,
    issuer_public_key: CLIssuerPublicKey,
    patient_public_key: CLUserPublicKey,
    credential: CLCredential,
    user_secret_key: Any,
    disclosed_indices: Sequence[int],
    expiry_index: int,
    T: int,
    B: int,
    nonce: bytes,
    G_range: Any,
    H_range: Any,
) -> CLRangePresentationProof:
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("nonce must be bytes")
    if B < 0:
        raise ValueError("B must be non-negative")

    q = params.order
    num_attributes = len(params.H_attrs)

    disclosed_sorted, hidden_sorted = _validate_partition(num_attributes, disclosed_indices)

    if expiry_index < 0 or expiry_index >= num_attributes:
        raise ValueError("expiry_index out of range")
    if expiry_index in disclosed_sorted:
        raise ValueError("expiry_index must remain hidden")

    attrs_bn = [_mod(m, q) for m in credential.attributes]
    disclosed_attributes: Dict[int, Any] = {i: attrs_bn[i] for i in disclosed_sorted}

    m_exp_int = int(attrs_bn[expiry_index])
    delta = m_exp_int - int(T)

    if delta < 0 or delta > B:
        raise ValueError(f"range constraint failed: delta={delta} not in [0, {B}]")

    ell = _ceil_log2(B + 1)
    bits = _bit_decompose(delta, ell)

    # Step 1. Randomize signature
    rrand = q.random()
    sigma_prime = credential.sigma + point_mul(params.g1, rrand, q)

    # Step 2. Blind CL witnesses
    rrand_blind = q.random()
    skuser_blind = q.random()

    hidden_attr_blinds: Dict[int, Any] = {}
    for i in hidden_sorted:
        hidden_attr_blinds[i] = q.random()

    # Step 3. Expiry commitment and linkage commitment
    r_exp = q.random()
    C_exp = point_mul(G_range, m_exp_int, q) + point_mul(H_range, r_exp, q)

    m_exp_blind = hidden_attr_blinds[expiry_index]
    r_exp_blind = q.random()
    R_exp = point_mul(G_range, m_exp_blind, q) + point_mul(H_range, r_exp_blind, q)

    # Step 4. Bit commitments
    C_bits: List[Any] = []
    r_bits: List[Any] = []

    for i in range(ell):
        r_i = q.random()
        bit_value = bits[i] * (2 ** i)
        C_i = point_mul(G_range, bit_value, q) + point_mul(H_range, r_i, q)
        C_bits.append(C_i)
        r_bits.append(r_i)

    k_sum = _bn(0)
    for r_i in r_bits:
        k_sum = (k_sum + _bn(r_i)).mod(q)
    k_sum = (k_sum - _bn(r_exp)).mod(q)

    # Step 5. Sigma-OR commitments
    v = q.random()
    C_v = point_mul(H_range, v, q)

    sigma_or_commitments: List[Any] = []
    sigma_or_responses: List[tuple[Any, Any, Any, Any, Any]] = []

    for i in range(ell):
        Y_i0 = C_bits[i]
        Y_i1 = C_bits[i] + point_mul(G_range, -(2 ** i), q)

        if bits[i] == 0:
            w_i0 = q.random()
            R_i0 = point_mul(H_range, w_i0, q)

            c_i1 = q.random()
            s_i1 = q.random()
            R_i1 = point_mul(H_range, s_i1, q) + point_mul(Y_i1, -c_i1, q)

            sigma_or_commitments.extend([R_i0, R_i1])
            sigma_or_responses.append((None, c_i1, None, s_i1, w_i0))
        else:
            w_i1 = q.random()
            R_i1 = point_mul(H_range, w_i1, q)

            c_i0 = q.random()
            s_i0 = q.random()
            R_i0 = point_mul(H_range, s_i0, q) + point_mul(Y_i0, -c_i0, q)

            sigma_or_commitments.extend([R_i0, R_i1])
            sigma_or_responses.append((c_i0, None, s_i0, None, w_i1))

    # Step 6. CL commitment A
    H_hidden_blind = point_mul(params.g1, skuser_blind, q)
    for i in hidden_sorted:
        H_hidden_blind = H_hidden_blind + point_mul(params.H_attrs[i], hidden_attr_blinds[i], q)

    e_g1_g2 = params.group.pair(params.g1, params.g2)
    A = (e_g1_g2 ** _bn(rrand_blind)) * params.group.pair(H_hidden_blind, issuer_public_key.pk)

    # Step 7. Unified challenge
    c = _hash_range_transcript(
        q=q,
        sigma_prime=sigma_prime,
        A_commitment=A,
        C_exp=C_exp,
        R_exp=R_exp,
        C_bits=C_bits,
        C_sum_commitment=C_v,
        sigma_or_reconstructed=sigma_or_commitments,
        issuer_pk=issuer_public_key.pk,
        patient_pk=patient_public_key.pk,
        T=T,
        B=B,
        nonce=bytes(nonce),
    )

    # Step 8. Responses
    rrand_tilde = (rrand_blind + c * _bn(rrand)).mod(q)
    skuser_tilde = (skuser_blind + c * _bn(user_secret_key.y)).mod(q)

    hidden_attr_responses: Dict[int, Any] = {}
    for i in hidden_sorted:
        hidden_attr_responses[i] = (hidden_attr_blinds[i] + c * attrs_bn[i]).mod(q)

    r_exp_tilde = (r_exp_blind + c * _bn(r_exp)).mod(q)
    s_sum = (_bn(v) + k_sum * c).mod(q)

    final_sigma_or: List[tuple[Any, Any, Any, Any]] = []

    for i in range(ell):
        if bits[i] == 0:
            _, c_i1, _, s_i1, w_i0 = sigma_or_responses[i]
            c_i0 = (c - c_i1).mod(q)
            s_i0 = (_bn(w_i0) + c_i0 * _bn(r_bits[i])).mod(q)
            final_sigma_or.append((c_i0, c_i1, s_i0, s_i1))
        else:
            c_i0, _, s_i0, _, w_i1 = sigma_or_responses[i]
            c_i1 = (c - c_i0).mod(q)
            s_i1 = (_bn(w_i1) + c_i1 * _bn(r_bits[i])).mod(q)
            final_sigma_or.append((c_i0, c_i1, s_i0, s_i1))

    return CLRangePresentationProof(
        sigma_prime=sigma_prime,
        c=c,
        rrand_tilde=rrand_tilde,
        skuser_tilde=skuser_tilde,
        hidden_attr_responses=hidden_attr_responses,
        disclosed_attributes=disclosed_attributes,
        hidden_indices=hidden_sorted,
        disclosed_indices=disclosed_sorted,
        expiry_index=expiry_index,
        C_exp=C_exp,
        r_exp_tilde=r_exp_tilde,
        C_bits=C_bits,
        s_sum=s_sum,
        sigma_or=final_sigma_or,
        T=int(T),
        B=int(B),
        nonce=bytes(nonce),
    )


# ============================================================
# Proof verification
# ============================================================

def verify_presentation_proof_with_range(
    params: CLPublicParameters,
    issuer_public_key: CLIssuerPublicKey,
    patient_public_key: CLUserPublicKey,
    proof: CLRangePresentationProof,
    G_range: Any,
    H_range: Any,
) -> bool:
    q = params.order
    num_attributes = len(params.H_attrs)

    if proof.B < 0:
        return False

    ell = _ceil_log2(proof.B + 1)

    if len(proof.C_bits) != ell:
        return False
    if len(proof.sigma_or) != ell:
        return False

    disclosed_sorted, hidden_sorted = _validate_partition(num_attributes, proof.disclosed_indices)

    if disclosed_sorted != proof.disclosed_indices:
        return False
    if hidden_sorted != proof.hidden_indices:
        return False
    if set(proof.hidden_attr_responses.keys()) != set(hidden_sorted):
        return False
    if set(proof.disclosed_attributes.keys()) != set(disclosed_sorted):
        return False
    if proof.expiry_index not in hidden_sorted:
        return False

    # Step 1. H_disclosed
    H_disclosed = _sum_disclosed_commitment(params, proof.disclosed_attributes)

    # Step 2. H_tilde_hidden
    H_hidden_tilde = _sum_hidden_response_commitment(params, proof.hidden_attr_responses)

    # Step 3. H''_hidden
    H_hidden_reconstructed = point_mul(params.g1, proof.skuser_tilde, q) + H_hidden_tilde

    # Step 4. Reconstruct A'
    e_sigma_prime_g2 = params.group.pair(proof.sigma_prime, params.g2)
    e_H_disclosed_pk = params.group.pair(H_disclosed, issuer_public_key.pk)
    e_g1_g2 = params.group.pair(params.g1, params.g2)
    e_Hhidden_pk = params.group.pair(H_hidden_reconstructed, issuer_public_key.pk)

    proof_relation = e_sigma_prime_g2 * (e_H_disclosed_pk ** (-_bn(1)))
    A_reconstructed = (proof_relation ** (-_bn(proof.c))) * (e_g1_g2 ** _bn(proof.rrand_tilde)) * e_Hhidden_pk

    # Step 5. Reconstruct linkage commitment R'_exp
    m_exp_tilde = proof.hidden_attr_responses[proof.expiry_index]
    R_exp_reconstructed = (
        point_mul(G_range, m_exp_tilde, q)
        + point_mul(H_range, proof.r_exp_tilde, q)
        + point_mul(proof.C_exp, -proof.c, q)
    )

    # Step 6. Reconstruct C'_v
    C_delta = proof.C_exp + point_mul(G_range, -proof.T, q)

    C_sum = point_mul(params.g1, 0, q)
    for C_i in proof.C_bits:
        C_sum = C_sum + C_i
    C_sum = C_sum + point_mul(C_delta, -1, q)

    # IMPORTANT:
    # C'_v = s_sum * H_range - c * C_sum
    C_v_reconstructed = point_mul(H_range, proof.s_sum, q) + point_mul(C_sum, -proof.c, q)

    # Step 7. Reconstruct Sigma-OR commitments
    sigma_or_reconstructed: List[Any] = []

    for i in range(ell):
        c_i0, c_i1, s_i0, s_i1 = proof.sigma_or[i]

        if (_bn(c_i0) + _bn(c_i1)).mod(q) != _bn(proof.c).mod(q):
            return False

        Y_i0 = proof.C_bits[i]
        Y_i1 = proof.C_bits[i] + point_mul(G_range, -(2 ** i), q)

        R_i0_reconstructed = point_mul(H_range, s_i0, q) + point_mul(Y_i0, -c_i0, q)
        R_i1_reconstructed = point_mul(H_range, s_i1, q) + point_mul(Y_i1, -c_i1, q)

        sigma_or_reconstructed.extend([R_i0_reconstructed, R_i1_reconstructed])

    # Step 8. Recompute global challenge
    c_check = _hash_range_transcript(
        q=q,
        sigma_prime=proof.sigma_prime,
        A_commitment=A_reconstructed,
        C_exp=proof.C_exp,
        R_exp=R_exp_reconstructed,
        C_bits=proof.C_bits,
        C_sum_commitment=C_v_reconstructed,
        sigma_or_reconstructed=sigma_or_reconstructed,
        issuer_pk=issuer_public_key.pk,
        patient_pk=patient_public_key.pk,
        T=proof.T,
        B=proof.B,
        nonce=proof.nonce,
    )

    return c_check == proof.c