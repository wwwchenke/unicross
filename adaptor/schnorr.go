package adaptor

import (
	"crypto/rand"
	"hash"
	"io"
	"math/big"
	vc "volley/curve"
)

type Signature struct {
	E *big.Int
	S *big.Int
}

type Point struct {
	X *big.Int
	Y *big.Int
}

func SchnorrSignAdaptor(msg []byte, yPoint vc.FastPoint, secret *big.Int, h hash.Hash, random io.Reader) (*Signature,
	error) {
	N := fastCurve.Params().N
	k, err := rand.Int(random, N)
	if err != nil {
		return nil, err
	}

	rPoint := fastCurve.FastBaseScalar(k.Bytes())
	//yPoint := fastCurve.NewPoint()
	//yPoint.From(y.X, y.Y)
	fastCurve.FastPointAdd(rPoint, rPoint, yPoint)
	rx, _ := rPoint.Back()
	data := make([]byte, len(msg)+bnLength)

	copy(data, msg)
	rx.FillBytes(data[len(msg):])
	h.Reset()
	h.Write(data)
	digest := h.Sum(nil)

	shiftSize := h.Size()*8 - fastCurve.Params().BitSize
	e := new(big.Int).SetBytes(digest)
	if shiftSize > 0 {
		e.Rsh(e, uint(shiftSize))
	}
	e.Mod(e, N)
	s := new(big.Int).Mul(e, secret)
	s.Mod(s, N)
	s.Sub(N, s)
	s.Add(s, k)
	s.Mod(s, N)

	return &Signature{
		E: e,
		S: s,
	}, nil
}

func SchnorrPreVerifyAdaptor(sig *Signature, msg []byte, y vc.FastPoint, public vc.FastPoint, h hash.Hash) bool {
	N := fastCurve.Params().N
	if sig.S.Sign() == 0 {
		return false
	}
	if sig.E.Cmp(N) >= 0 || sig.S.Cmp(N) >= 0 {
		return false
	}
	rPoint := fastCurve.FastBaseScalar(sig.S.Bytes())
	tmp := fastCurve.NewPoint()
	//tmp.From(public.X, public.Y)
	fastCurve.FastScalarMult(tmp, public, sig.E.Bytes())
	fastCurve.FastPointAdd(rPoint, rPoint, tmp)
	//tmp.From(y.X, y.Y)
	fastCurve.FastPointAdd(rPoint, rPoint, y)
	rx, _ := rPoint.Back()

	data := make([]byte, len(msg)+bnLength)

	copy(data, msg)
	rx.FillBytes(data[len(msg):])
	h.Reset()
	h.Write(data)
	digest := h.Sum(nil)

	shiftSize := h.Size()*8 - fastCurve.Params().BitSize
	e := new(big.Int).SetBytes(digest)
	if shiftSize > 0 {
		e.Rsh(e, uint(shiftSize))
	}
	e.Mod(e, N)
	return e.Cmp(sig.E) == 0
}

func SchnorrVerify(sig *Signature, msg []byte, public vc.FastPoint, h hash.Hash) bool {
	N := fastCurve.Params().N
	if sig.S.Sign() == 0 {
		return false
	}
	if sig.E.Cmp(N) >= 0 || sig.S.Cmp(N) >= 0 {
		return false
	}
	rPoint := fastCurve.FastBaseScalar(sig.S.Bytes())
	tmp := fastCurve.NewPoint()
	//tmp.From(public.X, public.Y)
	fastCurve.FastScalarMult(tmp, public, sig.E.Bytes())
	fastCurve.FastPointAdd(rPoint, rPoint, tmp)

	rx, _ := rPoint.Back()

	data := make([]byte, len(msg)+bnLength)

	copy(data, msg)
	rx.FillBytes(data[len(msg):])
	h.Reset()
	h.Write(data)
	digest := h.Sum(nil)

	shiftSize := h.Size()*8 - fastCurve.Params().BitSize
	e := new(big.Int).SetBytes(digest)
	if shiftSize > 0 {
		e.Rsh(e, uint(shiftSize))
	}
	e.Mod(e, N)
	return e.Cmp(sig.E) == 0
}
