package lpr_test

import (
	"crypto/rand"
	"testing"
	"volley/lpr"
)

func BenchmarkRLWEEncryption(b *testing.B) {
	d := int32(1024)
	q := int32(65536)
	t := int32(8)
	b.Logf("D = %d, Q = %d, t = %d\n", d, q, t)

	secret, err := lpr.GenSecret(d, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	public, err := lpr.GenPublicKey(secret, q, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	data, err := lpr.GenerateRq(d, t, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	plain := &lpr.Plaintext{
		Data: data,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = lpr.Encrypt(public, plain, q, t, rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkRLWEDecryption(b *testing.B) {
	d := int32(1024)
	q := int32(65536)
	t := int32(8)
	b.Logf("D = %d, Q = %d, t = %d\n", d, q, t)
	secret, err := lpr.GenSecret(d, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	public, err := lpr.GenPublicKey(secret, q, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	data, err := lpr.GenerateRq(d, t, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	plain := &lpr.Plaintext{
		Data: data,
	}
	cipher, _, err := lpr.Encrypt(public, plain, q, t, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = lpr.Decrypt(secret, cipher, q, t)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkLWEDecryption(b *testing.B) {
	d := int32(1024)
	q := int32(65536)
	t := int32(8)
	b.Logf("D = %d, Q = %d, t = %d\n", d, q, t)
	secret, err := lpr.GenSecret(d, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	public, err := lpr.GenPublicKey(secret, q, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	data, err := lpr.GenerateRq(d, t, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	plain := &lpr.Plaintext{
		Data: data,
	}
	cipher, _, err := lpr.Encrypt(public, plain, q, t, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	lweCipher := lpr.Extract(cipher, q, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lpr.LWEDecrypt(lweCipher, secret, q, t)
	}
	b.StopTimer()
}
