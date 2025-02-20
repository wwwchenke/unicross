package lpr

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestLPREncryption(test *testing.T) {
	d := int32(1024)
	q := int32(65536)
	t := int32(16)

	secret, err := GenSecret(d, rand.Reader)
	if err != nil {
		test.Fatal(err)
	}

	public, err := GenPublicKey(secret, q, rand.Reader)
	if err != nil {
		test.Fatal(err)
	}
	poly, err := GenerateRq(d, t/4, rand.Reader)
	if err != nil {
		test.Fatal(err)
	}
	plain := &Plaintext{
		Data: poly,
	}
	poly2, err := GenerateRq(d, t/4, rand.Reader)
	if err != nil {
		test.Fatal(err)
	}
	plain2 := &Plaintext{
		Data: poly2,
	}

	cipher, _, err := Encrypt(public, plain, q, t, rand.Reader)
	if err != nil {
		test.Fatal(err)
	}
	cipher2, _, err := Encrypt(public, plain2, q, t, rand.Reader)
	if err != nil {
		test.Fatal(err)
	}

	r, err := Decrypt(secret, cipher, q, t)
	if err != nil {
		test.Fatal(err)
	}

	for i, p := range poly {
		if p != r.Data[i] {
			fmt.Printf("Recovery error: %d, %d, %d\n", i, p, r.Data[i])
		}
	}
	for i := int32(0); i < d; i++ {
		lwe := Extract(cipher2, q, int(i))
		data := LWEDecrypt(lwe, secret, q, t)
		if data != poly2[i] {
			fmt.Printf("LWE recovery error: %d, %d, %d\n", i, data, poly2[i])
		}
	}

	cipherSum := CipherAdd(cipher, cipher2, q)
	for i := int32(0); i < d; i++ {
		lwe := Extract(cipherSum, q, int(i))
		data := LWEDecrypt(lwe, secret, q, t)
		if data != poly[i]+poly2[i] {
			fmt.Printf("LWE recovery error: %d, %d, %d\n", i, data, poly[i]+poly2[i])
		}
	}
	plainSum, err := Decrypt(secret, cipherSum, q, t)
	if err != nil {
		test.Fatal(err)
	}
	for i := int32(0); i < d; i++ {
		if plainSum.Data[i] != poly[i]+poly2[i] {
			fmt.Printf("LWE recovery error: %d, %d, %d\n", i, plainSum.Data[i], poly[i]+poly2[i])
		}
	}
}
