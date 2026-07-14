// Package bbs04 implements a research proof-of-concept of the Boneh-Boyen-
// Shacham 2004 short group signature over BLS12-381. It is intended for
// functional validation and measurement, not production deployment.
package bbs04

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const domain = "EPRX-BBS04-BLS12381-v1"

type GroupPublicKey struct {
	G1, H, U, V bls.G1Affine
	G2, W       bls.G2Affine
}
type GroupManagerKey struct{ Xi1, Xi2, Gamma fr.Element }
type MemberKey struct {
	A bls.G1Affine
	X fr.Element
}
type GroupSignature struct {
	T1, T2, T3                             bls.G1Affine
	C, SAlpha, SBeta, SX, SDelta1, SDelta2 fr.Element
}

func scalar() (fr.Element, error) {
	for {
		var x fr.Element
		if _, err := x.SetRandom(); err != nil {
			return x, err
		}
		if !x.IsZero() {
			return x, nil
		}
	}
}
func bi(x *fr.Element) *big.Int { var z big.Int; x.BigInt(&z); return &z }
func mul(p *bls.G1Affine, x *fr.Element) bls.G1Affine {
	var r bls.G1Affine
	r.ScalarMultiplication(p, bi(x))
	return r
}
func add(a, b *bls.G1Affine) bls.G1Affine { var r bls.G1Affine; r.Add(a, b); return r }
func sub(a, b *bls.G1Affine) bls.G1Affine { var r bls.G1Affine; r.Sub(a, b); return r }
func subScaled(a *bls.G1Affine, x *fr.Element, b *bls.G1Affine, y *fr.Element) bls.G1Affine {
	ax, by := mul(a, x), mul(b, y)
	return sub(&ax, &by)
}

func Setup() (*GroupPublicKey, *GroupManagerKey, error) {
	_, _, g1, g2 := bls.Generators()
	x1, e := scalar()
	if e != nil {
		return nil, nil, e
	}
	x2, e := scalar()
	if e != nil {
		return nil, nil, e
	}
	gamma, e := scalar()
	if e != nil {
		return nil, nil, e
	}
	hSeed, e := scalar()
	if e != nil {
		return nil, nil, e
	}
	h := mul(&g1, &hSeed)
	var i1, i2 fr.Element
	i1.Inverse(&x1)
	i2.Inverse(&x2)
	u, v := mul(&h, &i1), mul(&h, &i2)
	var w bls.G2Affine
	w.ScalarMultiplication(&g2, bi(&gamma))
	return &GroupPublicKey{G1: g1, G2: g2, H: h, U: u, V: v, W: w}, &GroupManagerKey{Xi1: x1, Xi2: x2, Gamma: gamma}, nil
}

func IssueMemberKey(gpk *GroupPublicKey, gmk *GroupManagerKey) (*MemberKey, error) {
	if gpk == nil || gmk == nil {
		return nil, errors.New("nil key")
	}
	for {
		x, e := scalar()
		if e != nil {
			return nil, e
		}
		var d fr.Element
		d.Add(&gmk.Gamma, &x)
		if d.IsZero() {
			continue
		}
		var inv fr.Element
		inv.Inverse(&d)
		a := mul(&gpk.G1, &inv)
		return &MemberKey{A: a, X: x}, nil
	}
}

func pair(p *bls.G1Affine, q *bls.G2Affine) (bls.GT, error) {
	return bls.Pair([]bls.G1Affine{*p}, []bls.G2Affine{*q})
}
func gtExp(x *bls.GT, s *fr.Element) bls.GT { var z bls.GT; z.Exp(*x, bi(s)); return z }
func gtMul(xs ...*bls.GT) bls.GT {
	var z bls.GT
	z.SetOne()
	for _, x := range xs {
		z.Mul(&z, x)
	}
	return z
}

func transcript(m []byte, t1, t2, t3, r1, r2 *bls.G1Affine, r3 *bls.GT, r4, r5 *bls.G1Affine) fr.Element {
	h := sha256.New()
	put := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	put([]byte(domain))
	put(m)
	for _, p := range []*bls.G1Affine{t1, t2, t3, r1, r2} {
		b := p.Bytes()
		put(b[:])
	}
	b3 := r3.Bytes()
	put(b3[:])
	for _, p := range []*bls.G1Affine{r4, r5} {
		b := p.Bytes()
		put(b[:])
	}
	var c fr.Element
	c.SetBytes(h.Sum(nil))
	return c
}

func Sign(gpk *GroupPublicKey, member *MemberKey, message []byte) (*GroupSignature, error) {
	if gpk == nil || member == nil {
		return nil, errors.New("nil key")
	}
	a, e := scalar()
	if e != nil {
		return nil, e
	}
	b, e := scalar()
	if e != nil {
		return nil, e
	}
	t1, t2 := mul(&gpk.U, &a), mul(&gpk.V, &b)
	var ab fr.Element
	ab.Add(&a, &b)
	ah := mul(&gpk.H, &ab)
	t3 := add(&member.A, &ah)
	var d1, d2 fr.Element
	d1.Mul(&member.X, &a)
	d2.Mul(&member.X, &b)
	ra, e := scalar()
	if e != nil {
		return nil, e
	}
	rb, e := scalar()
	if e != nil {
		return nil, e
	}
	rx, e := scalar()
	if e != nil {
		return nil, e
	}
	rd1, e := scalar()
	if e != nil {
		return nil, e
	}
	rd2, e := scalar()
	if e != nil {
		return nil, e
	}
	r1, r2 := mul(&gpk.U, &ra), mul(&gpk.V, &rb)
	eT3, e := pair(&t3, &gpk.G2)
	if e != nil {
		return nil, e
	}
	ehw, e := pair(&gpk.H, &gpk.W)
	if e != nil {
		return nil, e
	}
	ehg, e := pair(&gpk.H, &gpk.G2)
	if e != nil {
		return nil, e
	}
	var nab, nrd fr.Element
	nab.Add(&ra, &rb)
	nab.Neg(&nab)
	nrd.Add(&rd1, &rd2)
	nrd.Neg(&nrd)
	x1, x2, x3 := gtExp(&eT3, &rx), gtExp(&ehw, &nab), gtExp(&ehg, &nrd)
	r3 := gtMul(&x1, &x2, &x3)
	r4 := subScaled(&t1, &rx, &gpk.U, &rd1)
	r5 := subScaled(&t2, &rx, &gpk.V, &rd2)
	c := transcript(message, &t1, &t2, &t3, &r1, &r2, &r3, &r4, &r5)
	resp := func(r, w *fr.Element) fr.Element { var cw, z fr.Element; cw.Mul(&c, w); z.Add(r, &cw); return z }
	return &GroupSignature{T1: t1, T2: t2, T3: t3, C: c, SAlpha: resp(&ra, &a), SBeta: resp(&rb, &b), SX: resp(&rx, &member.X), SDelta1: resp(&rd1, &d1), SDelta2: resp(&rd2, &d2)}, nil
}

func Verify(gpk *GroupPublicKey, message []byte, s *GroupSignature) bool {
	if gpk == nil || s == nil {
		return false
	}
	r1 := subScaled(&gpk.U, &s.SAlpha, &s.T1, &s.C)
	r2 := subScaled(&gpk.V, &s.SBeta, &s.T2, &s.C)
	eT3, e := pair(&s.T3, &gpk.G2)
	if e != nil {
		return false
	}
	ehw, e := pair(&gpk.H, &gpk.W)
	if e != nil {
		return false
	}
	ehg, e := pair(&gpk.H, &gpk.G2)
	if e != nil {
		return false
	}
	etw, e := pair(&s.T3, &gpk.W)
	if e != nil {
		return false
	}
	eg, e := pair(&gpk.G1, &gpk.G2)
	if e != nil {
		return false
	}
	var n1, n2 fr.Element
	n1.Add(&s.SAlpha, &s.SBeta)
	n1.Neg(&n1)
	n2.Add(&s.SDelta1, &s.SDelta2)
	n2.Neg(&n2)
	x1, x2, x3 := gtExp(&eT3, &s.SX), gtExp(&ehw, &n1), gtExp(&ehg, &n2)
	var egInv, ratio bls.GT
	egInv.Inverse(&eg)
	ratio.Mul(&etw, &egInv)
	x4 := gtExp(&ratio, &s.C)
	r3 := gtMul(&x1, &x2, &x3, &x4)
	r4 := subScaled(&s.T1, &s.SX, &gpk.U, &s.SDelta1)
	r5 := subScaled(&s.T2, &s.SX, &gpk.V, &s.SDelta2)
	c := transcript(message, &s.T1, &s.T2, &s.T3, &r1, &r2, &r3, &r4, &r5)
	return c.Equal(&s.C)
}

func Open(gmk *GroupManagerKey, s *GroupSignature) (bls.G1Affine, error) {
	if gmk == nil || s == nil {
		return bls.G1Affine{}, errors.New("nil input")
	}
	x1 := mul(&s.T1, &gmk.Xi1)
	x2 := mul(&s.T2, &gmk.Xi2)
	z := sub(&s.T3, &x1)
	z = sub(&z, &x2)
	return z, nil
}
func CertificateID(a *bls.G1Affine) string { b := a.Bytes(); return fmt.Sprintf("%x", b[:]) }
func PublicKeySize() int                   { return 4*bls.SizeOfG1AffineCompressed + 2*bls.SizeOfG2AffineCompressed }
func ManagerKeySize() int                  { return 3 * fr.Bytes }
func MemberKeySize() int                   { return bls.SizeOfG1AffineCompressed + fr.Bytes }
func SignatureSize() int                   { return 3*bls.SizeOfG1AffineCompressed + 6*fr.Bytes }
