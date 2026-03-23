from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from bplib.bp import BpGroup
from petlib.bn import Bn


BytesLike = Union[bytes, str]


# ============================================================
# Helpers
# ============================================================

def _to_bytes(x: BytesLike) -> bytes:
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return x.encode("utf-8")
    raise TypeError("message must be bytes or str")


def _bn(x: Any) -> Bn:
    if isinstance(x, Bn):
        return x
    return Bn.from_num(x)


def _rand_scalar(q: Bn) -> Bn:
    """Return random nonzero scalar in Z_q*."""
    while True:
        x = q.random()
        if x != 0:
            return x


def _mod(x: Any, q: Bn) -> Bn:
    return _bn(x).mod(q)


def _inv_mod(x: Any, q: Bn) -> Bn:
    x_bn = _bn(x).mod(q)
    return x_bn.mod_inverse(q)


def point_mul(P: Any, k: Any, q: Bn) -> Any:
    """Elliptic-curve scalar multiplication with petlib.bn.Bn."""
    k_bn = _bn(k).mod(q)
    return P.mul(k_bn)


def serialize_elem(elem: Any) -> bytes:
    """
    Best-effort element serialization for hashing and registry lookup.
    You may only need to adjust this helper if your local bplib build differs.
    """
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
    """Hash arbitrary parts to a scalar in Z_q."""
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, (bytes, bytearray)):
            raw = bytes(part)
        else:
            raw = serialize_elem(part)
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
    return Bn.from_binary(h.digest()).mod(q)


def gt_pow(gt_elem: Any, k: Any, q: Optional[Bn] = None) -> Any:
    """
    Exponentiation in GT.
    In many bplib builds, GTElem supports `** Bn`.
    """
    k_bn = _bn(k)
    if q is not None:
        k_bn = k_bn.mod(q)
    return gt_elem ** k_bn


# ============================================================
# Data classes
# ============================================================

@dataclass
class GroupPublicKey:
    group: BpGroup
    order: Bn
    g1: Any
    g2: Any
    h: Any
    u: Any
    v: Any
    omega: Any


@dataclass
class ManagerKey:
    """
    README lists manager private key as (xi1, xi2), but gamma is also required
    to issue member keys A = g1^(1/(gamma + x)).
    """
    order: Bn
    xi1: Bn
    xi2: Bn
    gamma: Bn
    registry_by_A: Dict[bytes, str] = field(default_factory=dict)
    registry_full: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class MemberKey:
    order: Bn
    A: Any
    x: Bn
    member_id: Optional[str] = None


# ============================================================
# BBS04 core functions
# ============================================================

def setup() -> tuple[GroupPublicKey, ManagerKey]:
    """
    BBS04 setup.

    Public key:
        (g1, g2, h, u, v, omega)

    Manager secret:
        (xi1, xi2, gamma)
    """
    G = BpGroup()
    q = G.order()  # keep as Bn

    g1_base = G.gen1()
    g2_base = G.gen2()

    # Fresh random generators / points
    g1 = point_mul(g1_base, _rand_scalar(q), q)
    g2 = point_mul(g2_base, _rand_scalar(q), q)
    h = point_mul(g1_base, _rand_scalar(q), q)

    xi1 = _rand_scalar(q)
    xi2 = _rand_scalar(q)
    gamma = _rand_scalar(q)

    # Multiplicative notation in README:
    #   u^{xi1} = h, v^{xi2} = h
    # Additive EC notation:
    #   xi1 * u = h, xi2 * v = h
    u = point_mul(h, _inv_mod(xi1, q), q)
    v = point_mul(h, _inv_mod(xi2, q), q)

    # omega = g2^gamma  -> additive notation: gamma * g2
    omega = point_mul(g2, gamma, q)

    gpk = GroupPublicKey(
        group=G,
        order=q,
        g1=g1,
        g2=g2,
        h=h,
        u=u,
        v=v,
        omega=omega,
    )

    gmk = ManagerKey(
        order=q,
        xi1=xi1,
        xi2=xi2,
        gamma=gamma,
    )

    return gpk, gmk


def join_issue_member_key(
    group_public_key: GroupPublicKey,
    manager_key: ManagerKey,
    member_id: Optional[str] = None,
) -> MemberKey:
    """
    Issue BBS04 member private key (A, x) where:
        A = g1^(1/(gamma + x))
    """
    q = group_public_key.order
    x = _rand_scalar(q)

    denom = (manager_key.gamma + x).mod(q)
    if denom == 0:
        # astronomically unlikely, but avoid inverse(0)
        return join_issue_member_key(group_public_key, manager_key, member_id)

    A = point_mul(group_public_key.g1, _inv_mod(denom, q), q)

    mk = MemberKey(
        order=q,
        A=A,
        x=x,
        member_id=member_id,
    )

    # Registry for opening
    A_ser = serialize_elem(A)
    resolved_id = member_id if member_id is not None else A_ser.hex()
    manager_key.registry_by_A[A_ser] = resolved_id
    manager_key.registry_full[A_ser.hex()] = {
        "member_id": resolved_id,
        "x_dec": str(x),
        "A_ser_hex": A_ser.hex(),
    }

    return mk


def sign(
    message: BytesLike,
    member_key: MemberKey,
    group_public_key: GroupPublicKey,
) -> Dict[str, Any]:
    """
    BBS04 signing.

    Signature:
        (T1, T2, T3, c, s_alpha, s_beta, s_x, s_delta1, s_delta2)
    """
    msg = _to_bytes(message)
    q = group_public_key.order
    G = group_public_key.group

    alpha = _rand_scalar(q)
    beta = _rand_scalar(q)

    # T1 = u^alpha, T2 = v^beta, T3 = A * h^(alpha+beta)
    # Additive notation:
    T1 = point_mul(group_public_key.u, alpha, q)
    T2 = point_mul(group_public_key.v, beta, q)
    T3 = member_key.A + point_mul(group_public_key.h, (alpha + beta).mod(q), q)

    r_alpha = _rand_scalar(q)
    r_beta = _rand_scalar(q)
    r_x = _rand_scalar(q)
    r_delta1 = _rand_scalar(q)
    r_delta2 = _rand_scalar(q)

    delta1 = (member_key.x * alpha).mod(q)
    delta2 = (member_key.x * beta).mod(q)

    # R1 = u^{r_alpha}, R2 = v^{r_beta}
    R1 = point_mul(group_public_key.u, r_alpha, q)
    R2 = point_mul(group_public_key.v, r_beta, q)

    # Pairings
    e_T3_g2 = G.pair(T3, group_public_key.g2)
    e_h_omega = G.pair(group_public_key.h, group_public_key.omega)
    e_h_g2 = G.pair(group_public_key.h, group_public_key.g2)

    # R3 = e(T3,g2)^{r_x} * e(h,omega)^{-r_alpha-r_beta} * e(h,g2)^{-r_delta1-r_delta2}
    R3 = (
        gt_pow(e_T3_g2, r_x, q)
        * gt_pow(e_h_omega, -(r_alpha + r_beta), q)
        * gt_pow(e_h_g2, -(r_delta1 + r_delta2), q)
    )

    # R4 = T1^{r_x} * u^{-r_delta1}
    # R5 = T2^{r_x} * v^{-r_delta2}
    # Additive notation:
    R4 = point_mul(T1, r_x, q) + point_mul(group_public_key.u, -r_delta1, q)
    R5 = point_mul(T2, r_x, q) + point_mul(group_public_key.v, -r_delta2, q)

    c = hash_to_scalar(
        q,
        msg,
        T1, T2, T3,
        R1, R2, R3, R4, R5
    )

    s_alpha = (r_alpha + c * alpha).mod(q)
    s_beta = (r_beta + c * beta).mod(q)
    s_x = (r_x + c * member_key.x).mod(q)
    s_delta1 = (r_delta1 + c * delta1).mod(q)
    s_delta2 = (r_delta2 + c * delta2).mod(q)

    return {
        "T1": T1,
        "T2": T2,
        "T3": T3,
        "c": c,
        "s_alpha": s_alpha,
        "s_beta": s_beta,
        "s_x": s_x,
        "s_delta1": s_delta1,
        "s_delta2": s_delta2,
    }


def verify(
    message: BytesLike,
    signature: Dict[str, Any],
    group_public_key: GroupPublicKey,
) -> bool:
    """
    BBS04 verification.
    """
    msg = _to_bytes(message)
    q = group_public_key.order
    G = group_public_key.group

    T1 = signature["T1"]
    T2 = signature["T2"]
    T3 = signature["T3"]
    c = _bn(signature["c"])
    s_alpha = _bn(signature["s_alpha"])
    s_beta = _bn(signature["s_beta"])
    s_x = _bn(signature["s_x"])
    s_delta1 = _bn(signature["s_delta1"])
    s_delta2 = _bn(signature["s_delta2"])

    # R1_bar = u^{s_alpha} * T1^{-c}
    R1_bar = point_mul(group_public_key.u, s_alpha, q) + point_mul(T1, -c, q)

    # R2_bar = v^{s_beta} * T2^{-c}
    R2_bar = point_mul(group_public_key.v, s_beta, q) + point_mul(T2, -c, q)

    # Pairings for R3_bar
    e_T3_g2 = G.pair(T3, group_public_key.g2)
    e_h_omega = G.pair(group_public_key.h, group_public_key.omega)
    e_h_g2 = G.pair(group_public_key.h, group_public_key.g2)
    e_T3_omega = G.pair(T3, group_public_key.omega)
    e_g1_g2 = G.pair(group_public_key.g1, group_public_key.g2)

    # R3_bar = e(T3,g2)^{s_x} * e(h,omega)^{-s_alpha-s_beta}
    #          * e(h,g2)^{-s_delta1-s_delta2} * (e(T3,omega)/e(g1,g2))^c
    R3_bar = (
        gt_pow(e_T3_g2, s_x, q)
        * gt_pow(e_h_omega, -(s_alpha + s_beta), q)
        * gt_pow(e_h_g2, -(s_delta1 + s_delta2), q)
        * gt_pow(e_T3_omega, c, q)
        * gt_pow(e_g1_g2, -c, q)
    )

    # R4_bar = T1^{s_x} * u^{-s_delta1}
    R4_bar = point_mul(T1, s_x, q) + point_mul(group_public_key.u, -s_delta1, q)

    # R5_bar = T2^{s_x} * v^{-s_delta2}
    R5_bar = point_mul(T2, s_x, q) + point_mul(group_public_key.v, -s_delta2, q)

    c_bar = hash_to_scalar(
        q,
        msg,
        T1, T2, T3,
        R1_bar, R2_bar, R3_bar, R4_bar, R5_bar
    )

    return c_bar == c


def open(
    message: BytesLike,
    signature: Dict[str, Any],
    manager_key: ManagerKey,
) -> Dict[str, Any]:
    """
    Open a BBS04 signature.

    README formula:
        A = T3 / (T1^{xi1} * T2^{xi2})

    Additive notation:
        A = T3 - xi1*T1 - xi2*T2
    """
    _ = _to_bytes(message)  # kept for API consistency
    q = manager_key.order

    T1 = signature["T1"]
    T2 = signature["T2"]
    T3 = signature["T3"]

    A_rec = T3 + point_mul(T1, -manager_key.xi1, q) + point_mul(T2, -manager_key.xi2, q)
    A_ser = serialize_elem(A_rec)

    return {
        "A": A_rec,
        "A_ser_hex": A_ser.hex(),
        "member_id": manager_key.registry_by_A.get(A_ser),
        "registry_entry": manager_key.registry_full.get(A_ser.hex()),
    }


# ============================================================
# Optional smoke test
# ============================================================

if __name__ == "__main__":
    # ------------------------------------------------------------
    # 1. System setup (performed once by the Medical Authority)
    # ------------------------------------------------------------
    # Generates the group public key (gpk) used by everyone to verify
    # signatures and the group manager key (gmk) used only by the
    # authority to trace a signer if accountability is required.

    gpk, gmk = setup()


    # ------------------------------------------------------------
    # 2. Member enrollment (doctor joins the group)
    # ------------------------------------------------------------
    # The Medical Authority issues a unique member private key to
    # a doctor. The key corresponds to the doctor's licensed identity
    # but the identity is hidden during normal signature verification.

    mkey = join_issue_member_key(
        gpk,
        gmk,
        member_id="doctor:lic-ON-48291"
    )


    # ------------------------------------------------------------
    # 3. Message to be anonymously signed
    # ------------------------------------------------------------
    # In the prescription system this would be the serialized
    # ephemeral prescription public key (pk_pres) generated by
    # the doctor for the prescription session.

    message = b"ephemeral-prescription-public-key-12345"


    # ------------------------------------------------------------
    # 4. Anonymous signing by the doctor
    # ------------------------------------------------------------
    # The doctor signs the message using the group member key.
    # The resulting signature proves that a valid group member
    # created the signature, without revealing which doctor.

    sigma = sign(message, mkey, gpk)


    # ------------------------------------------------------------
    # 5. Public verification (performed by pharmacy or verifier)
    # ------------------------------------------------------------
    # Anyone possessing the group public key can verify that the
    # signature was produced by a legitimate group member.

    ok = verify(message, sigma, gpk)


    # ------------------------------------------------------------
    # 6. Opening / tracing (performed only by the authority)
    # ------------------------------------------------------------
    # If necessary (e.g., dispute or abuse), the authority can
    # "open" the signature using the manager key to reveal the
    # identity of the signer.

    opened = open(message, sigma, gmk)


    # ------------------------------------------------------------
    # 7. Display verification and tracing results
    # ------------------------------------------------------------

    print("valid?", ok)

    print(json.dumps(
        {
            # recovered identity of the doctor who signed
            "member_id": opened["member_id"],

            # prefix of the recovered member credential A
            # (used internally to map to the registry)
            "A_ser_hex_prefix": opened["A_ser_hex"][:32],

            # confirms that the recovered credential exists
            # in the authority's enrollment registry
            "has_registry_entry": opened["registry_entry"] is not None,
        },
        indent=2
    ))
