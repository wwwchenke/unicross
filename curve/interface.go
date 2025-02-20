package curve

import (
	"crypto/elliptic"
	"math/big"
)

type FastPoint interface {
	Back() (*big.Int, *big.Int)
	From(*big.Int, *big.Int)
	CopyFrom(FastPoint)
	IsZero() bool
	Neg()
	GenTable(bool)
	ExportTable(bool) []byte
	ImportTable([]byte, bool)
}

type FastBn interface {
	Back() []byte
	From(*big.Int)
	CopyFrom(FastBn)
}

type FastCurve interface {
	elliptic.Curve
	NewBn() FastBn
	NewPoint() FastPoint
	FastPointAdd(FastPoint, FastPoint, FastPoint)
	FastBaseScalar([]byte) FastPoint
	FastScalarMult(FastPoint, FastPoint, []byte)
	FastPolynomial(FastPoint, []FastPoint, [][]byte)
	Inverse(*big.Int) *big.Int
	FastOrderMul(FastBn, FastBn, FastBn)
	FasterPolynomial(FastPoint, []FastPoint, [][]byte, bool)
}
