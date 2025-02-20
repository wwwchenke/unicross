package secp256k1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha512"
	"hash"
	"io"
	"math/big"
)

const (
	aesIV = "IV for ECDSA CTR"
)

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte) *big.Int {
	orderBits := 256
	orderBytes := 32
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func VerifyECDSA(public *ecdsa.PublicKey, msg, sig []byte, h hash.Hash, precomputes interface{}) bool {
	digest := h.Sum(msg)
	r, s, err := UnmarshalSig(sig)
	if err != nil {
		return false
	}
	return VerifyHash(public, digest, r, s, precomputes)
}

func VerifyHash(public *ecdsa.PublicKey, digest []byte, r, s *big.Int, precomputes interface{}) bool {
	params := p256k1Curve.params
	N := params.N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	e := hashToInt(digest)
	w := new(big.Int).ModInverse(s, N)

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	var x, y *big.Int
	// u1*g + u2*p
	if precomputes == nil {
		x, y = p256k1Curve.CombinedMult(public.X, public.Y, u1.Bytes(), u2.Bytes())
	} else {
		x, y = p256k1Curve.CombinedMultByPrecomputes(u1.Bytes(), u2.Bytes(), precomputes)
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func SignECDSA(rand io.Reader, pri *ecdsa.PrivateKey, msg []byte, h hash.Hash) ([]byte, error) {
	digest := h.Sum(msg)
	r, s, err := SignHash(rand, pri, digest)
	if err != nil {
		return nil, err
	}
	return MarshalSig(r, s), nil
}

func SignHash(rand io.Reader, pri *ecdsa.PrivateKey, digest []byte) (*big.Int, *big.Int, error) {
	// Randomly read one byte at ~50% rate
	select {
	case <-closedChannel:
	case <-closedChannel:
		var buf [1]byte
		rand.Read(buf[:])
	}

	// Get 256 bits of entropy from rand.
	entropy := make([]byte, 32)
	_, err := io.ReadFull(rand, entropy)
	if err != nil {
		return nil, nil, err
	}

	// Initialize an SHA-512 hash context; digest...
	md := sha512.New()
	md.Write(pri.D.Bytes()) // the private key,
	md.Write(entropy)       // the entropy,
	md.Write(digest)        // and the input hash;
	key := md.Sum(nil)[:32] // and compute ChopMD-256(SHA-512),

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	N := p256k1Curve.params.N
	var k, kInv, r, s *big.Int
	for {
		for {
			k, err = randFieldElement(csprng)
			if err != nil {
				return nil, nil, err
			}

			kInv = p256k1Curve.Inverse(k)

			r, _ = p256k1Curve.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
		}

		e := hashToInt(digest)
		s = new(big.Int).Mul(pri.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}
	return r, s, nil
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
var one = big.NewInt(1)

func randFieldElement(rand io.Reader) (k *big.Int, err error) {
	params := p256k1Curve.params
	// Note that for P-521 this will actually be 63 bits more than the order, as
	// division rounds down, but the extra bit is inconsequential.
	b := make([]byte, params.BitSize/8+8) // TODO: use params.N.BitLen()
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}
