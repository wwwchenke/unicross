package secp256k1

import (
	"encoding/binary"
	"math/big"
	vc "volley/curve"
)

func FastCurve() vc.FastCurve {
	return p256k1Curve
}

func nonAdjacentFormBE256(scalar []byte, w uint) [257]int8 {
	// This implementation is adapted from the one
	// in curve25519-dalek and is documented there:
	// https://github.com/dalek-cryptography/curve25519-dalek/blob/f630041af28e9a405255f98a8a93adca18e4315b/src/scalar.rs#L800-L871

	if w < 2 {
		panic("w must be at least 2 by the definition of NAF")
	} else if w > 8 {
		panic("NAF digits must fit in int8")
	}

	var nafData [257]int8
	var digits [5]uint64

	digits[0] = binary.BigEndian.Uint64(scalar[24:])
	digits[1] = binary.BigEndian.Uint64(scalar[16:])
	digits[2] = binary.BigEndian.Uint64(scalar[8:])
	digits[3] = binary.BigEndian.Uint64(scalar)

	width := uint64(1 << w)
	windowMask := uint64(width - 1)

	pos := uint(0)
	carry := uint64(0)
	for pos < 257 {
		indexU64 := pos / 64
		indexBit := pos % 64
		var bitBuf uint64
		if indexBit < 64-w {
			// This window's bits are contained in a single u64
			bitBuf = digits[indexU64] >> indexBit
		} else {
			// Combine the current 64 bits with bits from the next 64
			bitBuf = (digits[indexU64] >> indexBit) | (digits[1+indexU64] << (64 - indexBit))
		}

		// Add carry into the current window
		window := carry + (bitBuf & windowMask)

		if window&1 == 0 {
			// If the window value is even, preserve the carry and continue.
			// Why is the carry preserved?
			// If carry == 0 and window & 1 == 0,
			//    then the next carry should be 0
			// If carry == 1 and window & 1 == 0,
			//    then bit_buf & 1 == 1 so the next carry should be 1
			pos += 1
			continue
		}

		if window < width/2 {
			carry = 0
			nafData[pos] = int8(window)
		} else {
			carry = 1
			nafData[pos] = int8(window) - int8(width)
		}

		pos += w
	}
	return nafData
}

type Point struct {
	p     *point
	zero  bool
	table *[8]point
}

func (pt *Point) Back() (*big.Int, *big.Int) {
	if pt.zero {
		return big.NewInt(0), big.NewInt(0)
	}
	return pt.p.p256k1PointToAffine()
}

func (pt *Point) From(x, y *big.Int) {
	p := pt.p
	fromBig(p.xyz[0:4], x)
	fromBig(p.xyz[4:8], y)
	p256k1Mul(p.xyz[0:4], p.xyz[0:4], rr)
	p256k1Mul(p.xyz[4:8], p.xyz[4:8], rr)
	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0
	p.xyz[10] = 0
	p.xyz[11] = 0
	pt.zero = false
}

func (pt *Point) CopyFrom(p2 vc.FastPoint) {
	copy(pt.p.xyz[:], p2.(*Point).p.xyz[:])
	pt.zero = p2.(*Point).zero
	pt.table = p2.(*Point).table
}

func (pt *Point) IsZero() bool {
	return pt.zero
}

func (pt *Point) Neg() {
	p256k1Neg(pt.p.xyz[4:8])
	pt.table = nil
}

func (pt *Point) GenTable(affine bool) {
	var table [8]point
	var p2 point
	p256k1PointDoubleAsm(p2.xyz[:], pt.p.xyz[:])
	copy(table[0].xyz[:], pt.p.xyz[:])
	for j := 1; j < 8; j++ {
		p256k1PointAddAsm(table[j].xyz[:], table[j-1].xyz[:], p2.xyz[:])
	}
	if affine {
		for i := 0; i < 8; i++ {
			zInv := make([]uint64, 4)
			zInvSq := make([]uint64, 4)
			p256k1Inverse(zInv, table[i].xyz[8:12])
			p256k1Sqr(zInvSq, zInv, 1)
			p256k1Mul(zInv, zInv, zInvSq)

			p256k1Mul(table[i].xyz[0:4], table[i].xyz[0:4], zInvSq)
			p256k1Mul(table[i].xyz[4:8], table[i].xyz[4:8], zInv)
			table[i].xyz[8] = 0x1000003d1
			table[i].xyz[9] = 0
			table[i].xyz[10] = 0
			table[i].xyz[11] = 0
		}
	}
	pt.table = &table
}

func (pt *Point) ExportTable(affine bool) []byte {
	if pt.table == nil {
		pt.GenTable(affine)
	}
	var exportBytes []byte
	if affine {
		exportBytes = make([]byte, 8*64)
		for i := 0; i < 8; i++ {
			for j := 0; j < 8; j++ {
				binary.BigEndian.PutUint64(exportBytes[i*64+j*8:], pt.table[i].xyz[j])
			}
		}
	} else {
		exportBytes = make([]byte, 8*96)
		for i := 0; i < 8; i++ {
			for j := 0; j < 12; j++ {
				binary.BigEndian.PutUint64(exportBytes[i*96+j*8:], pt.table[i].xyz[j])
			}
		}
	}
	return exportBytes
}

func (pt *Point) ImportTable(precomputes []byte, affine bool) {
	if pt.table == nil {
		pt.table = new([8]point)
	}
	if affine {
		for i := 0; i < 8; i++ {
			for j := 0; j < 8; j++ {
				pt.table[i].xyz[j] = binary.BigEndian.Uint64(precomputes[i*64+j*8:])
			}
			pt.table[i].xyz[8] = 0x1000003d1
			pt.table[i].xyz[9] = 0
			pt.table[i].xyz[10] = 0
			pt.table[i].xyz[11] = 0
		}
	} else {
		for i := 0; i < 8; i++ {
			for j := 0; j < 12; j++ {
				pt.table[i].xyz[j] = binary.BigEndian.Uint64(precomputes[i*96+j*8:])
			}
		}
	}
}

func (c *curve) NewPoint() vc.FastPoint {
	return &Point{
		p:    new(point),
		zero: true,
	}
}

func (c *curve) FastPointAdd(fpr, fp1, fp2 vc.FastPoint) {
	p1 := fp1.(*Point)
	p2 := fp2.(*Point)
	pr := fpr.(*Point)
	if p1.zero {
		copy(pr.p.xyz[:], p2.p.xyz[:])
		pr.zero = p2.zero
		return
	}
	if p2.zero {
		copy(pr.p.xyz[:], p1.p.xyz[:])
		pr.zero = p1.zero
		return
	}

	sign := p256k1PointAddAsm(pr.p.xyz[:], p1.p.xyz[:], p2.p.xyz[:])
	if sign == 3 {
		p256k1PointDoubleAsm(pr.p.xyz[:], p2.p.xyz[:])
	}
	pr.zero = sign == 2
	pr.table = nil
}

func (c *curve) FastBaseScalar(scalar []byte) vc.FastPoint {
	scalarReversed := make([]uint64, 4)
	sm2CurveGetScalar(scalarReversed, scalar)

	r := &Point{
		p:     new(point),
		zero:  false,
		table: nil,
	}
	p256k1BaseMul(r.p, scalarReversed)
	return r
}

func (c *curve) FastScalarMult(fpr, fp vc.FastPoint, scalar []byte) {
	p := fp.(*Point)
	pr := fpr.(*Point)
	if p.zero {
		pr.zero = true
		return
	}
	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	p256k1Inverse(zInv, p.p.xyz[8:12])
	p256k1Sqr(zInvSq, zInv, 1)
	p256k1Mul(zInv, zInv, zInvSq)

	p256k1Mul(pr.p.xyz[0:4], p.p.xyz[0:4], zInvSq)
	p256k1Mul(pr.p.xyz[4:8], p.p.xyz[4:8], zInv)
	pr.p.xyz[8] = 0x1000003d1
	pr.p.xyz[9] = 0
	pr.p.xyz[10] = 0
	pr.p.xyz[11] = 0
	pr.ScalarMultKoblitz(scalar)
	pr.table = nil
}

func (c *curve) FastPolynomial(result vc.FastPoint, pList []vc.FastPoint, scalarList [][]byte) {
	num := len(scalarList)
	sum := FastCurve().NewPoint()
	tmp := FastCurve().NewPoint()
	start := 0
	end := 0
	for {
		end = start + 64
		if end > num {
			end = num
		}
		c.fastPolynomial(tmp, pList[start:end], scalarList[start:end])
		c.FastPointAdd(sum, sum, tmp)
		if end == num {
			result.CopyFrom(sum)
			return
		}
		start = end
	}
}

func (c *curve) fastPolynomial(result vc.FastPoint, pList []vc.FastPoint, scalarList [][]byte) {
	num := len(scalarList)
	tables := make([][]point, num)
	nafList := make([][257]int8, num)
	scalar := make([]byte, 32)
	for i := 0; i < num; i++ {
		tables[i] = make([]point, 8)
		var p2 point
		currentPoint := pList[i].(*Point)
		p256k1PointDoubleAsm(p2.xyz[:], currentPoint.p.xyz[:])
		copy(tables[i][0].xyz[:], currentPoint.p.xyz[:])
		for j := 1; j < 8; j++ {
			p256k1PointAddAsm(tables[i][j].xyz[:], tables[i][j-1].xyz[:], p2.xyz[:])
		}
		diff := 32 - len(scalarList[i])
		copy(scalar[diff:], scalarList[i])
		copy(scalar[:diff], zero32[:diff])
		nafList[i] = nonAdjacentFormBE256(scalar, 5)
	}
	var tmp point
	p := result.(*Point)
	zero := true
	for i := 256; i >= 0; i-- {
		if !zero {
			p256k1PointDoubleAsm(p.p.xyz[:], p.p.xyz[:])
		}
		for n := 0; n < num; n++ {
			v := nafList[n][i]
			if v > 0 {
				if zero {
					copy(p.p.xyz[:], tables[n][v/2].xyz[:])
					zero = false
				} else {
					sign := p256k1PointAddAsm(p.p.xyz[:], p.p.xyz[:], tables[n][v/2].xyz[:])
					if sign == 3 {
						p256k1PointDoubleAsm(p.p.xyz[:], tables[n][v/2].xyz[:])
					} else if sign == 2 {
						zero = true
					}
				}
			} else if v < 0 {
				if zero {
					copy(p.p.xyz[:], tables[n][-v/2].xyz[:])
					zero = false
				} else {
					copy(tmp.xyz[:], tables[n][-v/2].xyz[:])
					p256k1Neg(tmp.xyz[4:8])
					sign := p256k1PointAddAsm(p.p.xyz[:], p.p.xyz[:], tmp.xyz[:])
					if sign == 3 {
						p256k1PointDoubleAsm(p.p.xyz[:], tmp.xyz[:])
					} else if sign == 2 {
						zero = true
					}
				}
			}
		}

	}
	p.zero = zero
	if zero {
		for i := 0; i < 12; i++ {
			p.p.xyz[i] = 0
		}
	}
	p.table = nil
}

func (pt *Point) ScalarMultKoblitz(scalar []byte) {
	k1, k2, signK1, signK2 := splitK(scalar)
	var p1, p2, p1Neg, p2Neg point

	copy(p1.xyz[:], pt.p.xyz[:])
	copy(p1Neg.xyz[:], p1.xyz[:])
	p256k1Neg(p1Neg.xyz[4:8])
	copy(p2.xyz[:], p1.xyz[:])
	p256k1Mul(p2.xyz[0:4], p2.xyz[0:4], betaField)
	copy(p2Neg.xyz[:], p2.xyz[:])
	p256k1Neg(p2Neg.xyz[4:8])

	if signK1 == -1 {
		p1, p1Neg = p1Neg, p1
	}
	if signK2 == -1 {
		p2, p2Neg = p2Neg, p2
	}
	k1PosNAF, k1NegNAF := naf(k1)
	k2PosNAF, k2NegNAF := naf(k2)
	k1Len := len(k1PosNAF)
	k2Len := len(k2PosNAF)

	m := k1Len
	if m < k2Len {
		m = k2Len
	}
	var q point
	zero := true
	var k1BytePos, k1ByteNeg, k2BytePos, k2ByteNeg byte
	for i := 0; i < m; i++ {
		// Since we're going left-to-right, pad the front with 0s.
		if i < m-k1Len {
			k1BytePos = 0
			k1ByteNeg = 0
		} else {
			k1BytePos = k1PosNAF[i-(m-k1Len)]
			k1ByteNeg = k1NegNAF[i-(m-k1Len)]
		}
		if i < m-k2Len {
			k2BytePos = 0
			k2ByteNeg = 0
		} else {
			k2BytePos = k2PosNAF[i-(m-k2Len)]
			k2ByteNeg = k2NegNAF[i-(m-k2Len)]
		}

		for j := 7; j >= 0; j-- {
			// Q = 2 * Q
			if !zero {
				p256k1PointDoubleAsm(q.xyz[:], q.xyz[:])
			}
			//curve.doubleJacobian(qx, qy, qz, qx, qy, qz)
			if k1BytePos&0x80 == 0x80 {
				if !zero {
					p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p1.xyz[:], 0)
					//p256k1PointAddAsm(q.xyz[:], q.xyz[:], p1.xyz[:])
				} else {
					copy(q.xyz[:], p1.xyz[:])
					zero = false
				}
				//curve.addJacobian(qx, qy, qz, p1x, p1y, p1z, qx, qy, qz)
			} else if k1ByteNeg&0x80 == 0x80 {
				if !zero {
					p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p1Neg.xyz[:], 0)
					//p256k1PointAddAsm(q.xyz[:], q.xyz[:], p1Neg.xyz[:])
				} else {
					copy(q.xyz[:], p1Neg.xyz[:])
					zero = false
				}
				//curve.addJacobian(qx, qy, qz, p1x, p1yNeg, p1z, qx, qy, qz)
			}

			if k2BytePos&0x80 == 0x80 {
				if !zero {
					p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p2.xyz[:], 0)
					//p256k1PointAddAsm(q.xyz[:], q.xyz[:], p2.xyz[:])
				} else {
					copy(q.xyz[:], p2.xyz[:])
					zero = false
				}
				//curve.addJacobian(qx, qy, qz, p2x, p2y, p2z, qx, qy, qz)
			} else if k2ByteNeg&0x80 == 0x80 {
				if !zero {
					p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p2Neg.xyz[:], 0)
					//p256k1PointAddAsm(q.xyz[:], q.xyz[:], p2Neg.xyz[:])
				} else {
					copy(q.xyz[:], p2Neg.xyz[:])
					zero = false
				}
				//curve.addJacobian(qx, qy, qz, p2x, p2yNeg, p2z, qx, qy, qz)
			}

			k1BytePos <<= 1
			k1ByteNeg <<= 1
			k2BytePos <<= 1
			k2ByteNeg <<= 1
		}
	}
	copy(pt.p.xyz[:], q.xyz[:])
	pt.zero = zero
}

type Bn struct {
	data [4]uint64
}

func (bn *Bn) From(n *big.Int) {
	if n.Cmp(p256k1Curve.params.N) >= 0 {
		n.Mod(n, p256k1Curve.params.N)
	}
	fromBig(bn.data[:], n)
	p256k1OrdMul(bn.data[:], bn.data[:], ro[:])
}

func (bn *Bn) Back() []byte {
	data := make([]byte, 32)
	d := []uint64{1, 0, 0, 0}
	p256k1OrdMul(d, d, bn.data[:])
	p256k1LittleToBig(data, d[:])
	return data
}

func (bn *Bn) CopyFrom(b vc.FastBn) {
	copy(bn.data[:], b.(*Bn).data[:])
}

func (c *curve) NewBn() vc.FastBn {
	bn := new(Bn)
	bn.data[0] = 0x402da1732fc9bebf
	bn.data[1] = 0x4551231950b75fc4
	bn.data[2] = 0x1
	bn.data[3] = 0
	return bn
}

func (c *curve) FastOrderMul(r, a, b vc.FastBn) {
	p256k1OrdMul(r.(*Bn).data[:], a.(*Bn).data[:], b.(*Bn).data[:])
}

func (c *curve) FasterPolynomial(result vc.FastPoint, pList []vc.FastPoint, scalarList [][]byte, affine bool) {
	num := len(scalarList)
	sum := FastCurve().NewPoint()
	tmp := FastCurve().NewPoint()
	start := 0
	end := 0
	for {
		end = start + 64
		if end > num {
			end = num
		}
		c.fasterPolynomial(tmp, pList[start:end], scalarList[start:end], affine)
		c.FastPointAdd(sum, sum, tmp)
		if end == num {
			result.CopyFrom(sum)
			return
		}
		start = end
	}
}

func (c *curve) fasterPolynomial(result vc.FastPoint, pList []vc.FastPoint, scalarList [][]byte, affine bool) {
	num := len(scalarList)
	nafList := make([][257]int8, num)
	scalar := make([]byte, 32)
	for i := 0; i < num; i++ {
		diff := 32 - len(scalarList[i])
		copy(scalar[diff:], scalarList[i])
		copy(scalar[:diff], zero32[:diff])
		nafList[i] = nonAdjacentFormBE256(scalar, 5)
	}
	var tmp point
	p := result.(*Point)
	zero := true
	for i := 256; i >= 0; i-- {
		if !zero {
			p256k1PointDoubleAsm(p.p.xyz[:], p.p.xyz[:])
		}
		for n := 0; n < num; n++ {
			v := nafList[n][i]
			currentTable := pList[n].(*Point).table
			if v > 0 {
				if zero {
					copy(p.p.xyz[:], currentTable[v/2].xyz[:])
					zero = false
				} else {
					if affine {
						p256k1PointAddAffineAsm(p.p.xyz[:], p.p.xyz[:], currentTable[v/2].xyz[:], 0)
						x := p.p.xyz[0:4]
						z := p.p.xyz[8:12]
						if x[0]|x[1]|x[2]|x[3] == 0 {
							p256k1PointDoubleAsm(p.p.xyz[:], currentTable[v/2].xyz[:])
						} else if z[0]|z[1]|z[2]|z[3] == 0 {
							zero = true
						}
					} else {
						sign := p256k1PointAddAsm(p.p.xyz[:], p.p.xyz[:], currentTable[v/2].xyz[:])
						if sign == 3 {
							p256k1PointDoubleAsm(p.p.xyz[:], currentTable[v/2].xyz[:])
						} else if sign == 2 {
							zero = true
						}
					}
				}
			} else if v < 0 {
				if zero {
					copy(p.p.xyz[:], currentTable[-v/2].xyz[:])
					zero = false
				} else {
					if affine {
						p256k1PointAddAffineAsm(p.p.xyz[:], p.p.xyz[:], currentTable[-v/2].xyz[:], 1)
						x := p.p.xyz[0:4]
						z := p.p.xyz[8:12]
						if x[0]|x[1]|x[2]|x[3] == 0 {
							copy(tmp.xyz[:], currentTable[-v/2].xyz[:])
							p256k1Neg(tmp.xyz[4:8])
							p256k1PointDoubleAsm(p.p.xyz[:], tmp.xyz[:])
						} else if z[0]|z[1]|z[2]|z[3] == 0 {
							zero = true
						}

					} else {
						copy(tmp.xyz[:], currentTable[-v/2].xyz[:])
						p256k1Neg(tmp.xyz[4:8])
						sign := p256k1PointAddAsm(p.p.xyz[:], p.p.xyz[:], tmp.xyz[:])
						if sign == 3 {
							p256k1PointDoubleAsm(p.p.xyz[:], tmp.xyz[:])
						} else if sign == 2 {
							zero = true
						}
					}
				}
			}
		}

	}
	p.zero = zero
	if zero {
		for i := 0; i < 12; i++ {
			p.p.xyz[i] = 0
		}
	}
	p.table = nil
}
