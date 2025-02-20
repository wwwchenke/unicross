package secp256k1_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
	"volley/secp256k1"
)

func TestSignAndVerify(t *testing.T) {
	secp256k1.InitNAFTables(6)

	for i := 0; i < 1000; i++ {
		digest := make([]byte, 32)
		rand.Read(digest)
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, pri, digest)
		if err != nil {
			t.Fatal(err)
		}

		pub := &pri.PublicKey

		verified := ecdsa.Verify(pub, digest, r, s)
		if !verified {
			t.Fatal("Not verified")
		}
	}
}

func TestVerificationOnPrecomputes(t *testing.T) {
	secp256k1.InitNAFTables(9)
	curve := secp256k1.Curve()

	digest := make([]byte, 32)
	rand.Read(digest)
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var r, s *big.Int
	r, s, err = secp256k1.SignHash(rand.Reader, pri, digest)
	if err != nil {
		t.Fatal(err)
	}

	pub := &pri.PublicKey
	tables := curve.ComputePrecomputesForPoint(pub.X, pub.Y)

	verified := secp256k1.VerifyHash(pub, digest, r, s, tables)
	if !verified {
		t.Fatal("Not verified")
	}

}

func TestSignAndVerifyECDSA(t *testing.T) {
	secp256k1.InitNAFTables(9)
	curve := secp256k1.Curve()

	for i := 0; i < 10000; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		pri, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		sig, err := secp256k1.SignECDSA(rand.Reader, pri, msg, sha256.New())
		if err != nil {
			t.Fatal(err)
		}

		pub := &pri.PublicKey

		verified := secp256k1.VerifyECDSA(pub, msg, sig, sha256.New(), nil)
		if !verified {
			t.Fatal("Not verified")
		}
	}
}

func TestSignAndVerifyECDSAOnPrecomputes(t *testing.T) {
	secp256k1.InitNAFTables(8)
	curve := secp256k1.Curve()
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &pri.PublicKey
	precomputes := secp256k1.ComputePrecomputesForPoint(pub.X, pub.Y)

	for i := 0; i < 10000; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)

		sig, err := secp256k1.SignECDSA(rand.Reader, pri, msg, sha256.New())
		if err != nil {
			t.Fatal(err)
		}

		verified := secp256k1.VerifyECDSA(pub, msg, sig, sha256.New(), precomputes)
		if !verified {
			t.Fatal("Not verified")
		}
	}
}
