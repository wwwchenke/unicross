package secp256k1

import (
	"math/big"
)

type invertible interface {
	Inverse(k *big.Int) *big.Int
}

func (c *curve) Inverse(in *big.Int) *big.Int {
	//return new(big.Int).ModInverse(in, c.params.N)
	inField := make([]uint64, 4)
	fromBig(inField, in)
	var k uint64
	p256k1OrdMontInversePhase1(inField, inField, &k)
	if k > 256 {
		k = 512 - k
		exField := make([]uint64, 4)
		exField[k/64] = 1 << (k % 64)
		p256k1OrdMul(inField, inField, exField)
	}
	exField := []uint64{1, 0, 0, 0}
	p256k1OrdMul(inField, inField, exField)

	out := make([]byte, 32)
	p256k1LittleToBig(out, inField)
	return new(big.Int).SetBytes(out)
}

func (c *curve) CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	var r1, r2 point
	sm2CurveGetScalar(scalarReversed, baseScalar)
	r1IsInfinity := scalarIsZero(scalarReversed)
	p256k1BaseMul(&r1, scalarReversed)

	sm2CurveGetScalar(scalarReversed, scalar)
	r2IsInfinity := scalarIsZero(scalarReversed)
	fromBig(r2.xyz[0:4], maybeReduceModP(bigX))
	fromBig(r2.xyz[4:8], maybeReduceModP(bigY))
	p256k1Mul(r2.xyz[0:4], r2.xyz[0:4], rr[:])
	p256k1Mul(r2.xyz[4:8], r2.xyz[4:8], rr[:])

	// This sets r2's Z value to 1, in the Montgomery domain.
	r2.xyz[8] = 0x1000003d1
	r2.xyz[9] = 0x0
	r2.xyz[10] = 0x0
	r2.xyz[11] = 0x0

	r2.ScalarMultKoblitz(scalar)
	var sum, double point
	if !r1IsInfinity && !r2IsInfinity {
		addSign := p256k1PointAddAsm(sum.xyz[:], r1.xyz[:], r2.xyz[:])
		if addSign == 3 {
			p256k1PointDoubleAsm(double.xyz[:], r1.xyz[:])
			return double.p256k1PointToAffine()
		}
		return sum.p256k1PointToAffine()
	}
	if r1IsInfinity {
		return r2.p256k1PointToAffine()
	}
	return r1.p256k1PointToAffine()

}

func (c *curve) CombinedMultByPrecomputes(baseScalar, scalar []byte, precomputes interface{}) (x,
	y *big.Int) {
	scalarReversed := make([]uint64, 4)
	var r1, r2 point
	sm2CurveGetScalar(scalarReversed, baseScalar)
	r1IsInfinity := scalarIsZero(scalarReversed)
	p256k1BaseMul(&r1, scalarReversed)

	sm2CurveGetScalar(scalarReversed, scalar)
	r2IsInfinity := scalarIsZero(scalarReversed)

	supported := false
	if tables, ok := precomputes.(*[43][33 * 8]uint64); ok {
		r2.p256k1ScalarMultByPrecomputesNAF6(scalarReversed, tables)
		supported = true
	}
	if tables, ok := precomputes.(*[37][65 * 8]uint64); ok {
		r2.p256k1ScalarMultByPrecomputesNAF7(scalarReversed, tables)
		supported = true
	}
	if tables, ok := precomputes.(*[33][129 * 8]uint64); ok {
		r2.p256k1ScalarMultByPrecomputesNAF8(scalarReversed, tables)
		supported = true
	}
	if tables, ok := precomputes.(*[29][257 * 8]uint64); ok {
		r2.p256k1ScalarMultByPrecomputesNAF9(scalarReversed, tables)
		supported = true
	}
	if !supported {
		panic("Unsupported precomputes")
	}
	var sum, double point
	if !r1IsInfinity && !r2IsInfinity {
		addSign := p256k1PointAddAsm(sum.xyz[:], r1.xyz[:], r2.xyz[:])
		if addSign == 3 {
			p256k1PointDoubleAsm(double.xyz[:], r1.xyz[:])
			return double.p256k1PointToAffine()
		}
		return sum.p256k1PointToAffine()
	}
	if r1IsInfinity {
		return r2.p256k1PointToAffine()
	}
	return r1.p256k1PointToAffine()

}

func (c *curve) ComputePrecomputesForPoint(x, y *big.Int) interface{} {
	var p point
	fromBig(p.xyz[0:4], x)
	fromBig(p.xyz[4:8], y)
	p256k1Mul(p.xyz[0:4], p.xyz[0:4], rr[:])
	p256k1Mul(p.xyz[4:8], p.xyz[4:8], rr[:])

	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0x0
	p.xyz[10] = 0x0
	p.xyz[11] = 0x0

	if p256k1NAF6Tables != nil {
		return p256k1Curve.generateNAF6Tables(&p)
	}
	if p256k1NAF7Tables != nil {
		return p256k1Curve.generateNAF7Tables(&p)
	}
	if p256k1NAF8Tables != nil {
		return p256k1Curve.generateNAF8Tables(&p)
	}
	if p256k1NAF9Tables != nil {
		return p256k1Curve.generateNAF9Tables(&p)
	}
	return nil
}
