package bbs04

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"testing"
)

func fixture(t *testing.T) (*GroupPublicKey, *GroupManagerKey, *MemberKey) {
	t.Helper()
	p, m, e := Setup()
	if e != nil {
		t.Fatal(e)
	}
	k, e := IssueMemberKey(p, m)
	if e != nil {
		t.Fatal(e)
	}
	return p, m, k
}
func TestSignVerifyOpen(t *testing.T) {
	p, m, k := fixture(t)
	msg := []byte("prescription issuer key|timestamp")
	s, e := Sign(p, k, msg)
	if e != nil {
		t.Fatal(e)
	}
	if !Verify(p, msg, s) {
		t.Fatal("valid signature rejected")
	}
	a, e := Open(m, s)
	if e != nil || !a.Equal(&k.A) {
		t.Fatal("opened certificate mismatch")
	}
}
func TestModifiedMessageRejected(t *testing.T) {
	p, _, k := fixture(t)
	s, _ := Sign(p, k, []byte("a"))
	if Verify(p, []byte("b"), s) {
		t.Fatal("modified message accepted")
	}
}
func TestModifiedSignatureRejected(t *testing.T) {
	p, _, k := fixture(t)
	s, _ := Sign(p, k, []byte("a"))
	var one fr.Element
	one.SetOne()
	s.SX.Add(&s.SX, &one)
	if Verify(p, []byte("a"), s) {
		t.Fatal("modified signature accepted")
	}
}
func TestWrongGroupRejected(t *testing.T) {
	p, _, k := fixture(t)
	q, _, _ := fixture(t)
	s, _ := Sign(p, k, []byte("a"))
	if Verify(q, []byte("a"), s) {
		t.Fatal("wrong group accepted")
	}
}
func TestMembersOpeningAndRegistry(t *testing.T) {
	p, m, k1 := fixture(t)
	k2, e := IssueMemberKey(p, m)
	if e != nil {
		t.Fatal(e)
	}
	reg := map[string]string{CertificateID(&k1.A): "HP-1", CertificateID(&k2.A): "HP-2"}
	for i, k := range []*MemberKey{k1, k2} {
		s, _ := Sign(p, k, []byte("x"))
		if !Verify(p, []byte("x"), s) {
			t.Fatal("verify")
		}
		a, _ := Open(m, s)
		want := []string{"HP-1", "HP-2"}[i]
		if reg[CertificateID(&a)] != want {
			t.Fatal("registry lookup")
		}
	}
}
func TestSignaturesRandomized(t *testing.T) {
	p, _, k := fixture(t)
	a, _ := Sign(p, k, []byte("x"))
	b, _ := Sign(p, k, []byte("x"))
	if a.T1.Equal(&b.T1) && a.T2.Equal(&b.T2) && a.T3.Equal(&b.T3) {
		t.Fatal("signatures identical")
	}
}
