package secp256k1_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"
	"volley/secp256k1"
)

func BenchmarkSignatureNAF9(t *testing.B) {
	secp256k1.InitNAFTables(9)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pris := make([]*ecdsa.PrivateKey, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		pris[i] = pri
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023
		_, _, err := secp256k1.SignHash(rand.Reader, pris[index], digest[index])
		if err != nil {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkSignatureNAF8(t *testing.B) {
	secp256k1.InitNAFTables(8)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pris := make([]*ecdsa.PrivateKey, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		pris[i] = pri
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023
		_, _, err := secp256k1.SignHash(rand.Reader, pris[index], digest[index])
		if err != nil {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkSignatureNAF7(t *testing.B) {
	secp256k1.InitNAFTables(7)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pris := make([]*ecdsa.PrivateKey, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		pris[i] = pri
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023
		_, _, err := secp256k1.SignHash(rand.Reader, pris[index], digest[index])
		if err != nil {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkSignatureNAF6(t *testing.B) {
	secp256k1.InitNAFTables(6)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pris := make([]*ecdsa.PrivateKey, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		pris[i] = pri
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023
		_, _, err := secp256k1.SignHash(rand.Reader, pris[index], digest[index])
		if err != nil {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkVerificationNAF9(t *testing.B) {
	secp256k1.InitNAFTables(9)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pubs := make([]*ecdsa.PublicKey, dataNum)
	rList := make([]*big.Int, dataNum)
	sList := make([]*big.Int, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		rList[i], sList[i], err = secp256k1.SignHash(rand.Reader, pri, digest[i])
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = &pri.PublicKey
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023

		verified := secp256k1.VerifyHash(pubs[index], digest[index], rList[index], sList[index], nil)
		if !verified {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkVerificationNAF8(t *testing.B) {
	secp256k1.InitNAFTables(8)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pubs := make([]*ecdsa.PublicKey, dataNum)
	rList := make([]*big.Int, dataNum)
	sList := make([]*big.Int, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		rList[i], sList[i], err = secp256k1.SignHash(rand.Reader, pri, digest[i])
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = &pri.PublicKey
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023

		verified := secp256k1.VerifyHash(pubs[index], digest[index], rList[index], sList[index], nil)
		if !verified {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkVerificationNAF7(t *testing.B) {
	secp256k1.InitNAFTables(7)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pubs := make([]*ecdsa.PublicKey, dataNum)
	rList := make([]*big.Int, dataNum)
	sList := make([]*big.Int, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		rList[i], sList[i], err = secp256k1.SignHash(rand.Reader, pri, digest[i])
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = &pri.PublicKey
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023

		verified := secp256k1.VerifyHash(pubs[index], digest[index], rList[index], sList[index], nil)
		if !verified {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkVerificationNAF6(t *testing.B) {
	secp256k1.InitNAFTables(6)
	dataNum := 1024
	digest := make([][]byte, dataNum)
	pubs := make([]*ecdsa.PublicKey, dataNum)
	rList := make([]*big.Int, dataNum)
	sList := make([]*big.Int, dataNum)
	for i := 0; i < dataNum; i++ {
		pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		rList[i], sList[i], err = secp256k1.SignHash(rand.Reader, pri, digest[i])
		if err != nil {
			t.Fatal(err)
		}
		pubs[i] = &pri.PublicKey
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023

		verified := secp256k1.VerifyHash(pubs[index], digest[index], rList[index], sList[index], nil)
		if !verified {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}

func BenchmarkVerificationOnPrecomputes(t *testing.B) {
	secp256k1.InitNAFTables(9)
	pri, err := ecdsa.GenerateKey(secp256k1.Curve(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &pri.PublicKey
	precomputes := secp256k1.ComputePrecomputesForPoint(pub.X, pub.Y)

	dataNum := 1024
	digest := make([][]byte, dataNum)
	rList := make([]*big.Int, dataNum)
	sList := make([]*big.Int, dataNum)
	for i := 0; i < dataNum; i++ {
		digest[i] = make([]byte, 32)
		rand.Read(digest[i])
		rList[i], sList[i], err = secp256k1.SignHash(rand.Reader, pri, digest[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := i & 1023

		verified := secp256k1.VerifyHash(pub, digest[index], rList[index], sList[index], precomputes)
		if !verified {
			t.Fatal("Not verified")
		}
	}
	t.StopTimer()
}
