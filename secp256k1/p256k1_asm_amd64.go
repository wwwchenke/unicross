//go:build amd64
// +build amd64

package secp256k1

// Endianness swap
//go:noescape
func p256k1BigToLittle(res []uint64, in []byte)

//go:noescape
func p256k1LittleToBig(res []byte, in []uint64)

//go:noescape
func p256k1Neg(val []uint64)

//go:noescape
func p256k1Sqr(res, in []uint64, n int)

//go:noescape
func p256k1Mul(res, in1, in2 []uint64)

//go:noescape
func p256k1OrdMul(res, in1, in2 []uint64)

//go:noescape
func p256k1OrdSqr(res, in []uint64, n int)

//go:noescape
func p256k1FromMont(res, in []uint64)

//go:noescape
func p256k1PointAddAffineAsm(res, in1, in2 []uint64, sign int)

//go:noescape
func p256k1PointAddAsm(res, in1, in2 []uint64) int

//go:noescape
func p256k1PointDoubleAsm(res, in []uint64)

//go:noescape
func p256k1MontInversePhase1(res, in []uint64, k *uint64)

//go:noescape
func p256k1OrdMontInversePhase1(res, in []uint64, k *uint64)
