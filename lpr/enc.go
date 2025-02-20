package lpr

import (
	"io"
	"math"
)

var EMin int32 = -32
var EMax int32 = 32

type PrivateKey struct {
	Data []int32
}

type PublicKey struct {
	PK0 []int32
	PK1 []int32
}

type Plaintext struct {
	Data []int32
}

type Ciphertext struct {
	CT0 []int32
	CT1 []int32
}

type LWECiphertext struct {
	B int32
	A []int32
}

type EncryptionRandom struct {
	U  []int32
	E1 []int32
	E2 []int32
}

func Encrypt(pub *PublicKey, plain *Plaintext, q, T int32, random io.Reader) (*Ciphertext, *EncryptionRandom, error) {
	d := int32(len(plain.Data))
	u, err := GenerateR2(d, random)
	if err != nil {
		return nil, nil, err
	}

	e1, err := GenerateR2(d, random)
	if err != nil {
		return nil, nil, err
	}

	e2, err := GenerateR2(d, random)
	if err != nil {
		return nil, nil, err
	}

	delta := q / T
	ct0 := PolyAdd(PolyAdd(PolyMul(pub.PK0, u, q), e1, q), PolyScalar(plain.Data, delta, q), q)
	ct1 := PolyAdd(PolyMul(pub.PK1, u, q), e2, q)
	return &Ciphertext{
			CT0: ct0,
			CT1: ct1,
		}, &EncryptionRandom{
			U:  u,
			E1: e1,
			E2: e2,
		}, nil
}

func Decrypt(pri *PrivateKey, cipher *Ciphertext, q, T int32) (*Plaintext, error) {
	tmp := PolyAdd(PolyMul(cipher.CT1, pri.Data, q), cipher.CT0, q)
	for i := 0; i < len(tmp); i++ {
		tmp[i] = int32(math.Round(float64(tmp[i]*T) / float64(q)))

		tmp[i] = tmp[i] % T
		if tmp[i] >= T/2 {
			tmp[i] -= T
		} else if tmp[i] < -T/2 {
			tmp[i] += T / 2
		}
	}
	return &Plaintext{
		Data: tmp,
	}, nil
}

func Extract(cipher *Ciphertext, q int32, i int) *LWECiphertext {
	lwe := new(LWECiphertext)
	lwe.B = cipher.CT0[i]
	d := len(cipher.CT1)
	a := make([]int32, d)
	for n := 0; n <= i; n++ {
		a[n] = cipher.CT1[i-n]
	}
	for n := i + 1; n < d; n++ {
		a[n] = -cipher.CT1[d-n+i]
		if a[n] == q/2 {
			a[n] = -q / 2
		}
	}
	lwe.A = a
	return lwe
}

func LWEDecrypt(lwe *LWECiphertext, pri *PrivateKey, Q, T int32) int32 {
	d := len(pri.Data)
	tmp := int64(lwe.B)
	for i := 0; i < d; i++ {
		tmp += int64(lwe.A[i]) * int64(pri.Data[i])
		tmp = tmp % int64(Q)
	}
	tmp = int64(math.Round(float64(tmp*int64(T)) / float64(Q)))
	tmp = tmp % int64(T)
	if tmp >= int64(T)/2 {
		tmp -= int64(T)
	} else if tmp < -int64(T)/2 {
		tmp += int64(T)
	}
	return int32(tmp)
}

func CipherAdd(c1, c2 *Ciphertext, q int32) *Ciphertext {
	d := len(c1.CT0)
	c3 := new(Ciphertext)
	c3.CT0 = make([]int32, d)
	c3.CT1 = make([]int32, d)
	for i := 0; i < d; i++ {
		ct0 := (int64(c1.CT0[i]) + int64(c2.CT0[i])) % int64(q)
		ct1 := (int64(c1.CT1[i]) + int64(c2.CT1[i])) % int64(q)
		if ct0 >= int64(q/2) {
			ct0 -= int64(q)
		} else if ct0 < -int64(q/2) {
			ct0 += int64(q)
		}
		if ct1 >= int64(q/2) {
			ct1 -= int64(q)
		} else if ct1 < -int64(q/2) {
			ct1 += int64(q)
		}
		c3.CT0[i] = int32(ct0)
		c3.CT1[i] = int32(ct1)
	}
	return c3
}
