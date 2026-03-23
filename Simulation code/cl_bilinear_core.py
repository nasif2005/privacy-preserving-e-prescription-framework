from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from bplib.bp import BpGroup
from petlib.bn import Bn


# ============================================================
# Helpers
# ============================================================

def _bn(x: Any) -> Bn:
    if isinstance(x, Bn):
        return x
    return Bn.from_num(x)


def _mod(x: Any, q: Bn) -> Bn:
    return _bn(x).mod(q)


def _rand_scalar_nonzero(q: Bn) -> Bn:
    while True:
        x = q.random()
        if x != 0:
            return x


def point_mul(P: Any, k: Any, q: Bn) -> Any:
    return P.mul(_bn(k).mod(q))


def serialize_elem(elem: Any) -> bytes:
    """
    Best-effort serialization for group elements and scalars.
    """
    if isinstance(elem, Bn):
        try:
            return elem.binary()
        except Exception:
            return str(int(elem)).encode("utf-8")

    for name in ("export", "to_bytes", "serialize"):
        if hasattr(elem, name):
            fn = getattr(elem, name)
            try:
                out = fn()
                if isinstance(out, bytes):
                    return out
                if isinstance(out, str):
                    return out.encode("utf-8")
            except Exception:
                pass

    try:
        return bytes(elem)
    except Exception:
        return repr(elem).encode("utf-8")


def hash_to_scalar(q: Bn, *parts: Any) -> Bn:
    """
    Fiat-Shamir hash to Z_q.
    """
    h = hashlib.sha256()
    for part in parts:
        raw = serialize_elem(part)
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
    return Bn.from_binary(h.digest()).mod(q)


# ============================================================
# Data classes
# ============================================================

@dataclass
class CLPublicParameters:
    group: BpGroup
    order: Bn
    g1: Any
    g2: Any
    H_attrs: List[Any]   # H1, ..., HL in G1


@dataclass
class CLIssuerSecretKey:
    x: Bn


@dataclass
class CLIssuerPublicKey:
    pk: Any  # x * g2 in G2


@dataclass
class CLUserSecretKey:
    y: Bn


@dataclass
class CLUserPublicKey:
    pk: Any  # y * g1 in G1


@dataclass
class CLCredentialRequest:
    """
    Issuance request sent from user to issuer.
    """
    H_commitment: Any
    c: Bn
    s_skuser: Bn
    s_attrs: List[Bn]
    nonce: bytes


@dataclass
class CLCredential:
    """
    Core credential object.
    """
    sigma: Any
    attributes: List[Bn]
    user_public_key: Any
    H_commitment: Any


# ============================================================
# Setup / Key generation
# ============================================================

def setup(num_attributes: int) -> CLPublicParameters:
    """
    Generate bilinear pairing public parameters and attribute generators.

    Public parameters:
        (q, G1, G2, GT, e, g1, g2, H1, ..., HL)
    """
    if num_attributes <= 0:
        raise ValueError("num_attributes must be positive")

    G = BpGroup()
    q = G.order()

    g1_base = G.gen1()
    g2_base = G.gen2()

    # Fresh random generators / independent-looking points
    g1 = point_mul(g1_base, _rand_scalar_nonzero(q), q)
    g2 = point_mul(g2_base, _rand_scalar_nonzero(q), q)

    H_attrs = [
        point_mul(g1_base, _rand_scalar_nonzero(q), q)
        for _ in range(num_attributes)
    ]

    return CLPublicParameters(
        group=G,
        order=q,
        g1=g1,
        g2=g2,
        H_attrs=H_attrs,
    )


def issuer_keygen(params: CLPublicParameters) -> tuple[CLIssuerSecretKey, CLIssuerPublicKey]:
    """
    Issuer selects x <- Z_q* and publishes pk_issuer = x * g2.
    """
    x = _rand_scalar_nonzero(params.order)
    pk = point_mul(params.g2, x, params.order)
    return CLIssuerSecretKey(x=x), CLIssuerPublicKey(pk=pk)


def user_keygen(params: CLPublicParameters) -> tuple[CLUserSecretKey, CLUserPublicKey]:
    """
    User selects y <- Z_q* and publishes pk_user = y * g1.
    """
    y = _rand_scalar_nonzero(params.order)
    pk = point_mul(params.g1, y, params.order)
    return CLUserSecretKey(y=y), CLUserPublicKey(pk=pk)


# ============================================================
# Commitment construction
# ============================================================

def _validate_attribute_count(params: CLPublicParameters, attributes: List[Any]) -> List[Bn]:
    if len(attributes) != len(params.H_attrs):
        raise ValueError(
            f"attribute count mismatch: expected {len(params.H_attrs)}, got {len(attributes)}"
        )
    return [_mod(m, params.order) for m in attributes]


def compute_attribute_commitment(params: CLPublicParameters, attributes: List[Any]) -> Any:
    """
    H_m = sum_i m_i * H_i
    """
    attrs_bn = _validate_attribute_count(params, attributes)
    Hm = point_mul(params.g1, 0, params.order)  # identity in G1
    for mi, Hi in zip(attrs_bn, params.H_attrs):
        Hm = Hm + point_mul(Hi, mi, params.order)
    return Hm


def compute_credential_commitment(
    params: CLPublicParameters,
    user_public_key: CLUserPublicKey,
    attributes: List[Any],
) -> Any:
    """
    H = pk_user + sum_i m_i * H_i
    """
    Hm = compute_attribute_commitment(params, attributes)
    return user_public_key.pk + Hm


# ============================================================
# Issuance request proof (Algorithm A.1 / A.2 style)
# ============================================================

def generate_issue_request_proof(
    params: CLPublicParameters,
    user_secret_key: CLUserSecretKey,
    attributes: List[Any],
    nonce: bytes,
) -> CLCredentialRequest:
    """
    Generate NIZK proof for well-formed credential commitment:
        proves knowledge of sk_user and all attributes used in H.

    Returns:
        H_commitment, c, s_skuser, s_attrs, nonce
    """
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError("nonce must be bytes")

    q = params.order
    attrs_bn = _validate_attribute_count(params, attributes)

    # Public commitment H = pk_user + sum_i m_i H_i
    user_pk = point_mul(params.g1, user_secret_key.y, q)
    H_commitment = compute_credential_commitment(
        params,
        CLUserPublicKey(pk=user_pk),
        attrs_bn,
    )

    # Blind user secret key
    sk_blind = q.random()
    pk_user_blind = point_mul(params.g1, sk_blind, q)

    # Blind attributes
    attr_blinds: List[Bn] = []
    Hm_blind = point_mul(params.g1, 0, q)
    for Hi in params.H_attrs:
        m_blind = q.random()
        attr_blinds.append(m_blind)
        Hm_blind = Hm_blind + point_mul(Hi, m_blind, q)

    # H' = pk'_user + Hm'
    H_blind = pk_user_blind + Hm_blind

    # Fiat-Shamir challenge
    c = hash_to_scalar(q, H_commitment, H_blind, nonce)

    # Responses
    s_skuser = (sk_blind + c * user_secret_key.y).mod(q)
    s_attrs = [
        (m_blind + c * mi).mod(q)
        for m_blind, mi in zip(attr_blinds, attrs_bn)
    ]

    return CLCredentialRequest(
        H_commitment=H_commitment,
        c=c,
        s_skuser=s_skuser,
        s_attrs=s_attrs,
        nonce=bytes(nonce),
    )


def verify_issue_request_proof(
    params: CLPublicParameters,
    request: CLCredentialRequest,
) -> bool:
    """
    Verify the issuance request proof.

    Reconstruct:
        H'' = (-c) * H + s_skuser * g1 + sum_i s_i * H_i
    and check:
        c == Hash(H || H'' || nonce)
    """
    q = params.order

    if len(request.s_attrs) != len(params.H_attrs):
        return False

    H_reconstructed = point_mul(request.H_commitment, -request.c, q)
    H_reconstructed = H_reconstructed + point_mul(params.g1, request.s_skuser, q)

    for s_i, Hi in zip(request.s_attrs, params.H_attrs):
        H_reconstructed = H_reconstructed + point_mul(Hi, s_i, q)

    c_check = hash_to_scalar(q, request.H_commitment, H_reconstructed, request.nonce)
    return c_check == request.c


# ============================================================
# Credential issuance / verification
# ============================================================

def issue_credential(
    params: CLPublicParameters,
    issuer_secret_key: CLIssuerSecretKey,
    request: CLCredentialRequest,
    attributes: List[Any],
    user_public_key: CLUserPublicKey,
    verify_request_first: bool = True,
) -> CLCredential:
    """
    Issuer verifies the issuance request proof, then computes:
        sigma = x * H
    where x is issuer secret key and H is the user commitment.

    The issuer also checks that the provided attributes and user public key
    are consistent with H_commitment.
    """
    attrs_bn = _validate_attribute_count(params, attributes)

    if verify_request_first and not verify_issue_request_proof(params, request):
        raise ValueError("issuance request proof verification failed")

    expected_H = compute_credential_commitment(params, user_public_key, attrs_bn)
    if serialize_elem(expected_H) != serialize_elem(request.H_commitment):
        raise ValueError("request commitment does not match supplied attributes/user public key")

    sigma = point_mul(request.H_commitment, issuer_secret_key.x, params.order)

    return CLCredential(
        sigma=sigma,
        attributes=attrs_bn,
        user_public_key=user_public_key.pk,
        H_commitment=request.H_commitment,
    )


def verify_credential_signature(
    params: CLPublicParameters,
    issuer_public_key: CLIssuerPublicKey,
    credential: CLCredential,
) -> bool:
    """
    Basic credential signature verification:
        e(sigma, g2) == e(H, pk_issuer)

    Since sigma = x * H and pk_issuer = x * g2.
    """
    left = params.group.pair(credential.sigma, params.g2)
    right = params.group.pair(credential.H_commitment, issuer_public_key.pk)
    return left == right


# ============================================================
# Convenience helper
# ============================================================

def build_and_issue_credential(
    params: CLPublicParameters,
    issuer_secret_key: CLIssuerSecretKey,
    user_secret_key: CLUserSecretKey,
    user_public_key: CLUserPublicKey,
    attributes: List[Any],
    nonce: bytes,
) -> tuple[CLCredentialRequest, CLCredential]:
    """
    Convenience end-to-end helper:
    - user generates issuance request proof
    - issuer verifies and issues credential
    """
    req = generate_issue_request_proof(
        params=params,
        user_secret_key=user_secret_key,
        attributes=attributes,
        nonce=nonce,
    )
    cred = issue_credential(
        params=params,
        issuer_secret_key=issuer_secret_key,
        request=req,
        attributes=attributes,
        user_public_key=user_public_key,
        verify_request_first=True,
    )
    return req, cred


# ============================================================
# Optional smoke test
# ============================================================

if __name__ == "__main__":
    # Example with 4 attributes:
    # prescription_id, medication_id, dosage, issue_date
    params = setup(num_attributes=4)

    isk, ipk = issuer_keygen(params)
    usk, upk = user_keygen(params)

    attrs = [
        1001,    # prescription identifier
        55,      # medication identifier
        2,       # dosage
        20260317 # issue date
    ]

    nonce = b"issue-request-nonce"

    req = generate_issue_request_proof(
        params=params,
        user_secret_key=usk,
        attributes=attrs,
        nonce=nonce,
    )

    ok_req = verify_issue_request_proof(params, req)
    print("issue request proof valid?", ok_req)

    cred = issue_credential(
        params=params,
        issuer_secret_key=isk,
        request=req,
        attributes=attrs,
        user_public_key=upk,
        verify_request_first=True,
    )

    ok_sig = verify_credential_signature(params, ipk, cred)
    print("credential signature valid?", ok_sig)
