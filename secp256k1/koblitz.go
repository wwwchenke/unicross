package secp256k1

import (
	"math/big"
)

func splitK(k []byte) ([]byte, []byte, int, int) {
	// All math here is done with big.Int, which is slow.
	// At some point, it might be useful to write something similar to
	// fieldVal but for N instead of P as the prime field if this ends up
	// being a bottleneck.
	bigIntK := new(big.Int)
	c1, c2 := new(big.Int), new(big.Int)
	tmp1, tmp2 := new(big.Int), new(big.Int)
	k1, k2 := new(big.Int), new(big.Int)

	bigIntK.SetBytes(k)
	// c1 = round(b2 * k / n) from step 4.
	// Rounding isn't really necessary and costs too much, hence skipped
	c1.Mul(b2, bigIntK)
	c1.Div(c1, p256k1Curve.params.N)
	// c2 = round(b1 * k / n) from step 4 (sign reversed to optimize one step)
	// Rounding isn't really necessary and costs too much, hence skipped
	c2.Mul(b1, bigIntK)
	c2.Div(c2, p256k1Curve.params.N)
	// k1 = k - c1 * a1 - c2 * a2 from step 5 (note c2's sign is reversed)
	tmp1.Mul(c1, a1)
	tmp2.Mul(c2, a2)
	k1.Sub(bigIntK, tmp1)
	k1.Add(k1, tmp2)
	// k2 = - c1 * b1 - c2 * b2 from step 5 (note c2's sign is reversed)
	tmp1.Mul(c1, b1)
	tmp2.Mul(c2, b2)
	k2.Sub(tmp2, tmp1)

	// Note Bytes() throws out the sign of k1 and k2. This matters
	// since k1 and/or k2 can be negative. Hence, we pass that
	// back separately.
	return k1.Bytes(), k2.Bytes(), k1.Sign(), k2.Sign()
}

func naf(k []byte) ([]byte, []byte) {
	// The essence of this algorithm is that whenever we have consecutive 1s
	// in the binary, we want to put a -1 in the lowest bit and get a bunch
	// of 0s up to the highest bit of consecutive 1s.  This is due to this
	// identity:
	// 2^n + 2^(n-1) + 2^(n-2) + ... + 2^(n-k) = 2^(n+1) - 2^(n-k)
	//
	// The algorithm thus may need to go 1 more bit than the length of the
	// bits we actually have, hence bits being 1 bit longer than was
	// necessary.  Since we need to know whether adding will cause a carry,
	// we go from right-to-left in this addition.
	var carry, curIsOne, nextIsOne bool
	// these default to zero
	retPos := make([]byte, len(k)+1)
	retNeg := make([]byte, len(k)+1)
	for i := len(k) - 1; i >= 0; i-- {
		curByte := k[i]
		for j := uint(0); j < 8; j++ {
			curIsOne = curByte&1 == 1
			if j == 7 {
				if i == 0 {
					nextIsOne = false
				} else {
					nextIsOne = k[i-1]&1 == 1
				}
			} else {
				nextIsOne = curByte&2 == 2
			}
			if carry {
				if curIsOne {
					// This bit is 1, so continue to carry
					// and don't need to do anything.
				} else {
					// We've hit a 0 after some number of
					// 1s.
					if nextIsOne {
						// Start carrying again since
						// a new sequence of 1s is
						// starting.
						retNeg[i+1] += 1 << j
					} else {
						// Stop carrying since 1s have
						// stopped.
						carry = false
						retPos[i+1] += 1 << j
					}
				}
			} else if curIsOne {
				if nextIsOne {
					// If this is the start of at least 2
					// consecutive 1s, set the current one
					// to -1 and start carrying.
					retNeg[i+1] += 1 << j
					carry = true
				} else {
					// This is a singleton, not consecutive
					// 1s.
					retPos[i+1] += 1 << j
				}
			}
			curByte >>= 1
		}
	}
	if carry {
		retPos[0] = 1
		return retPos, retNeg
	}
	return retPos[1:], retNeg[1:]
}

func (p *point) PolynomialKoblitz(points []point, scalarList [][]byte) {
	num := len(scalarList)

	p1List := make([]point, num)
	p1NegList := make([]point, num)
	p2List := make([]point, num)
	p2NegList := make([]point, num)
	k1PosNAFList := make([][]byte, num)
	k1NegNAFList := make([][]byte, num)
	k2PosNAFList := make([][]byte, num)
	k2NegNAFList := make([][]byte, num)
	m := 0
	var k1, k2 []byte
	var signK1, signK2 int
	for i, scalar := range scalarList {
		k1, k2, signK1, signK2 = splitK(scalar)
		copy(p1List[i].xyz[:], points[i].xyz[:])
		copy(p1NegList[i].xyz[:], p1List[i].xyz[:])
		if signK1 != -1 {
			p256k1Neg(p1NegList[i].xyz[4:8])
		} else {
			p256k1Neg(p1List[i].xyz[4:8])
		}
		if signK2 != -1 {
			copy(p2List[i].xyz[:], points[i].xyz[:])
			p256k1Mul(p2List[i].xyz[0:4], p2List[i].xyz[0:4], betaField)
			copy(p2NegList[i].xyz[:], p2List[i].xyz[:])
			p256k1Neg(p2NegList[i].xyz[4:8])
		} else {
			copy(p2NegList[i].xyz[:], points[i].xyz[:])
			p256k1Mul(p2NegList[i].xyz[0:4], p2NegList[i].xyz[0:4], betaField)
			copy(p2List[i].xyz[:], p2NegList[i].xyz[:])
			p256k1Neg(p2List[i].xyz[4:8])
		}

		k1PosNAFList[i], k1NegNAFList[i] = naf(k1)
		k2PosNAFList[i], k2NegNAFList[i] = naf(k2)
		if len(k1PosNAFList[i]) > m {
			m = len(k1PosNAFList[i])
		}
		if len(k2PosNAFList[i]) > m {
			m = len(k2PosNAFList[i])
		}
	}
	k1BytePos := make([]byte, num)
	k1ByteNeg := make([]byte, num)
	k2BytePos := make([]byte, num)
	k2ByteNeg := make([]byte, num)
	zero := true
	var q point
	for i := 0; i < m; i++ {
		for n := 0; n < num; n++ {
			if i < m-len(k1PosNAFList[n]) {
				k1BytePos[n] = 0
				k1ByteNeg[n] = 0
			} else {
				k1BytePos[n] = k1PosNAFList[n][i-(m-len(k1PosNAFList[n]))]
				k1ByteNeg[n] = k1NegNAFList[n][i-(m-len(k1PosNAFList[n]))]
			}
			if i < m-len(k2PosNAFList[n]) {
				k2BytePos[n] = 0
				k2ByteNeg[n] = 0
			} else {
				k2BytePos[n] = k2PosNAFList[n][i-(m-len(k2PosNAFList[n]))]
				k2ByteNeg[n] = k2NegNAFList[n][i-(m-len(k2PosNAFList[n]))]
			}
		}
		for j := 7; j >= 0; j-- {
			if !zero {
				p256k1PointDoubleAsm(q.xyz[:], q.xyz[:])
			}
			for n := 0; n < num; n++ {
				if k1BytePos[n]&0x80 == 0x80 {
					if !zero {
						p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p1List[n].xyz[:], 0)
					} else {
						copy(q.xyz[:], p1List[n].xyz[:])
						zero = false
					}
					//curve.addJacobian(qx, qy, qz, p1x, p1y, p1z, qx, qy, qz)
				} else if k1ByteNeg[n]&0x80 == 0x80 {
					if !zero {
						p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p1NegList[n].xyz[:], 0)
					} else {
						copy(q.xyz[:], p1NegList[n].xyz[:])
						zero = false
					}
				}

				if k2BytePos[n]&0x80 == 0x80 {
					if !zero {
						p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p2List[n].xyz[:], 0)
					} else {
						copy(q.xyz[:], p2List[n].xyz[:])
						zero = false
					}
					//curve.addJacobian(qx, qy, qz, p2x, p2y, p2z, qx, qy, qz)
				} else if k2ByteNeg[n]&0x80 == 0x80 {
					if !zero {
						p256k1PointAddAffineAsm(q.xyz[:], q.xyz[:], p2NegList[n].xyz[:], 0)
					} else {
						copy(q.xyz[:], p2NegList[n].xyz[:])
						zero = false
					}
					//curve.addJacobian(qx, qy, qz, p2x, p2yNeg, p2z, qx, qy, qz)
				}

				k1BytePos[n] <<= 1
				k1ByteNeg[n] <<= 1
				k2BytePos[n] <<= 1
				k2ByteNeg[n] <<= 1
			}
		}
	}
	copy(p.xyz[:], q.xyz[:])
}

func (p *point) ScalarMultKoblitz(scalar []byte) {
	k1, k2, signK1, signK2 := splitK(scalar)
	var p1, p2, p1Neg, p2Neg point
	//fromBig(p1.xyz[0:4], bigX)
	//fromBig(p1.xyz[4:8], bigY)
	//p256k1Mul(p1.xyz[0:4], p1.xyz[0:4], rr)
	//p256k1Mul(p1.xyz[4:8], p1.xyz[4:8], rr)
	//p1.xyz[8] = 0x1000003d1
	//p1.xyz[9] = 0x0
	//p1.xyz[10] = 0x0
	//p1.xyz[11] = 0x0
	copy(p1.xyz[:], p.xyz[:])
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
	copy(p.xyz[:], q.xyz[:])
}
