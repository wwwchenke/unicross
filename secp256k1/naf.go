package secp256k1

var p256k1NAF6Tables *[43][33 * 8]uint64

func (c *curve) generateNAF6Tables(p *point) *[43][33 * 8]uint64 {
	tables := new([43][33 * 8]uint64)

	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, p.xyz[:])

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)

	for j := 1; j <= 32; j++ {
		copy(t1, t2)
		for i := 0; i < 43; i++ {
			// The window size is 6 so we need to double 6 times.
			if i != 0 {
				for k := 0; k < 6; k++ {
					p256k1PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256k1Inverse(zInv, t1[8:12])
			p256k1Sqr(zInvSq, zInv, 1)
			p256k1Mul(zInv, zInv, zInvSq)

			p256k1Mul(t1[:4], t1[:4], zInvSq)
			p256k1Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], p.xyz[8:12])
			// Update the table entry
			copy(tables[i][j*8:], t1[:8])
		}
		if j == 1 {
			p256k1PointDoubleAsm(t2, p.xyz[:])
		} else {
			p256k1PointAddAsm(t2, t2, p.xyz[:])
		}
	}
	return tables
}

func initNAF6Tables() {
	basePoint := &point{
		xyz: [12]uint64{
			0xd7362e5a487e2097, 0x231e295329bc66db, 0x979f48c033fd129c, 0x9981e643e9089f48,
			0xb15ea6d2d3dbabe2, 0x8dfc5d5d1f1dc64d, 0x70b6b59aac19c136, 0xcf3f851fd4a582d6,
			0x1000003d1, 0x0, 0x0, 0x0,
		},
	}
	p256k1NAF6Tables = p256k1Curve.generateNAF6Tables(basePoint)
}

func p256k1BaseMulNAF6(p *point, scalar []uint64) {
	//precomputeOnce.Do(initTable)

	wvalue := (scalar[0] << 1) & 0x7f
	sel, sign := boothW6(uint(wvalue))
	//sm2CurveSelectBaseBeta(p.xyz[0:8], sm2Curve37WindowsTables[0][0:], sel)
	copy(p.xyz[0:8], p256k1NAF6Tables[0][sel*8:])
	if sign != 0 {
		p256k1Neg(p.xyz[4:8])
	}

	// (This is one, in the Montgomery domain.)
	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0x0
	p.xyz[10] = 0x0
	p.xyz[11] = 0x0

	t0 := make([]uint64, 8)

	index := uint(5)
	zero := sel
	//var t1 p256Point
	for i := 1; i < 43; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x7f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x7f
		}
		index += 6
		sel, sign = boothW6(uint(wvalue))
		copy(t0[0:8], p256k1NAF6Tables[i][sel*8:])
		//sm2CurveSelectBaseBeta(t0.xyz[0:8], sm2Curve37WindowsTables[i][0:], sel)
		if zero == 0 {
			if sign == 1 {
				p256k1Neg(t0[4:8])
			}
			copy(p.xyz[:], t0[0:8])
			p.xyz[8] = 0x1000003d1
			p.xyz[9] = 0
			p.xyz[10] = 0
			p.xyz[11] = 0
			//fmt.Println("happen 1")
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		//p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign, sel, zero)
		zero |= sel
	}
}

var p256k1NAF7Tables *[37][65 * 8]uint64

func (c *curve) generateNAF7Tables(p *point) *[37][65 * 8]uint64 {
	tables := new([37][65 * 8]uint64)

	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, p.xyz[:])

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)

	for j := 1; j <= 64; j++ {
		copy(t1, t2)
		for i := 0; i < 37; i++ {
			// The window size is 7 so we need to double 7 times.
			if i != 0 {
				for k := 0; k < 7; k++ {
					p256k1PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256k1Inverse(zInv, t1[8:12])
			p256k1Sqr(zInvSq, zInv, 1)
			p256k1Mul(zInv, zInv, zInvSq)

			p256k1Mul(t1[:4], t1[:4], zInvSq)
			p256k1Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], p.xyz[8:12])
			// Update the table entry
			copy(tables[i][j*8:], t1[:8])
		}
		if j == 1 {
			p256k1PointDoubleAsm(t2, p.xyz[:])
		} else {
			p256k1PointAddAsm(t2, t2, p.xyz[:])
		}
	}
	return tables
}

func initNAF7Tables() {
	basePoint := &point{
		xyz: [12]uint64{
			0xd7362e5a487e2097, 0x231e295329bc66db, 0x979f48c033fd129c, 0x9981e643e9089f48,
			0xb15ea6d2d3dbabe2, 0x8dfc5d5d1f1dc64d, 0x70b6b59aac19c136, 0xcf3f851fd4a582d6,
			0x1000003d1, 0x0, 0x0, 0x0,
		},
	}
	p256k1NAF7Tables = p256k1Curve.generateNAF7Tables(basePoint)
}

func p256k1BaseMulNAF7(p *point, scalar []uint64) {
	//precomputeOnce.Do(initTable)

	wvalue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wvalue))
	//sm2CurveSelectBaseBeta(p.xyz[0:8], sm2Curve37WindowsTables[0][0:], sel)
	copy(p.xyz[0:8], p256k1NAF7Tables[0][sel*8:])
	if sign != 0 {
		p256k1Neg(p.xyz[4:8])
	}

	// (This is one, in the Montgomery domain.)
	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0x0
	p.xyz[10] = 0x0
	p.xyz[11] = 0x0

	t0 := make([]uint64, 8)

	index := uint(6)
	zero := sel
	//var t1 p256Point
	for i := 1; i < 37; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0xff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0xff
		}
		index += 7
		sel, sign = boothW7(uint(wvalue))
		copy(t0[0:8], p256k1NAF7Tables[i][sel*8:])
		//sm2CurveSelectBaseBeta(t0.xyz[0:8], sm2Curve37WindowsTables[i][0:], sel)
		if zero == 0 {
			if sign == 1 {
				p256k1Neg(t0[4:8])
			}
			copy(p.xyz[:], t0[0:8])
			p.xyz[8] = 0x1000003d1
			p.xyz[9] = 0
			p.xyz[10] = 0
			p.xyz[11] = 0
			//fmt.Println("happen 1")
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		//p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign, sel, zero)
		zero |= sel
	}
}

var p256k1NAF8Tables *[33][129 * 8]uint64

func (c *curve) generateNAF8Tables(p *point) *[33][129 * 8]uint64 {
	tables := new([33][129 * 8]uint64)

	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, p.xyz[:])

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)

	for j := 1; j <= 128; j++ {
		copy(t1, t2)
		for i := 0; i < 33; i++ {
			// The window size is 8 so we need to double 8 times.
			if i != 0 {
				for k := 0; k < 8; k++ {
					p256k1PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256k1Inverse(zInv, t1[8:12])
			p256k1Sqr(zInvSq, zInv, 1)
			p256k1Mul(zInv, zInv, zInvSq)

			p256k1Mul(t1[:4], t1[:4], zInvSq)
			p256k1Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], p.xyz[8:12])
			// Update the table entry
			copy(tables[i][j*8:], t1[:8])
		}
		if j == 1 {
			p256k1PointDoubleAsm(t2, p.xyz[:])
		} else {
			p256k1PointAddAsm(t2, t2, p.xyz[:])
		}
	}
	return tables
}

func initNAF8Tables() {

	basePoint := &point{
		xyz: [12]uint64{
			0xd7362e5a487e2097, 0x231e295329bc66db, 0x979f48c033fd129c, 0x9981e643e9089f48,
			0xb15ea6d2d3dbabe2, 0x8dfc5d5d1f1dc64d, 0x70b6b59aac19c136, 0xcf3f851fd4a582d6,
			0x1000003d1, 0x0, 0x0, 0x0,
		},
	}
	p256k1NAF8Tables = p256k1Curve.generateNAF8Tables(basePoint)
}

func p256k1BaseMulNAF8(p *point, scalar []uint64) {
	//precomputeOnce.Do(initTable)

	wvalue := (scalar[0] << 1) & 0x1ff
	sel, sign := boothW8(uint(wvalue))
	//sm2CurveSelectBaseBeta(p.xyz[0:8], sm2Curve37WindowsTables[0][0:], sel)
	copy(p.xyz[0:8], p256k1NAF8Tables[0][sel*8:])
	if sign != 0 {
		p256k1Neg(p.xyz[4:8])
	}

	// (This is one, in the Montgomery domain.)
	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0x0
	p.xyz[10] = 0x0
	p.xyz[11] = 0x0

	t0 := make([]uint64, 8)

	index := uint(7)
	zero := sel
	//var t1 p256Point
	for i := 1; i < 33; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x1ff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x1ff
		}
		index += 8
		sel, sign = boothW8(uint(wvalue))
		copy(t0[0:8], p256k1NAF8Tables[i][sel*8:])
		//sm2CurveSelectBaseBeta(t0.xyz[0:8], sm2Curve37WindowsTables[i][0:], sel)
		if zero == 0 {
			if sign == 1 {
				p256k1Neg(t0[4:8])
			}
			copy(p.xyz[:], t0[0:8])
			p.xyz[8] = 0x1000003d1
			p.xyz[9] = 0
			p.xyz[10] = 0
			p.xyz[11] = 0
			//fmt.Println("happen 1")
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		//p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign, sel, zero)
		zero |= sel
	}
}

var p256k1NAF9Tables *[29][257 * 8]uint64

func (c *curve) generateNAF9Tables(p *point) *[29][257 * 8]uint64 {
	tables := new([29][257 * 8]uint64)

	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, p.xyz[:])

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)

	for j := 1; j <= 256; j++ {
		copy(t1, t2)
		for i := 0; i < 29; i++ {
			// The window size is 9 so we need to double 9 times.
			if i != 0 {
				for k := 0; k < 9; k++ {
					p256k1PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256k1Inverse(zInv, t1[8:12])
			p256k1Sqr(zInvSq, zInv, 1)
			p256k1Mul(zInv, zInv, zInvSq)

			p256k1Mul(t1[:4], t1[:4], zInvSq)
			p256k1Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], p.xyz[8:12])
			// Update the table entry
			copy(tables[i][j*8:], t1[:8])
		}
		if j == 1 {
			p256k1PointDoubleAsm(t2, p.xyz[:])
		} else {
			p256k1PointAddAsm(t2, t2, p.xyz[:])
		}
	}
	return tables
}

func initNAF9Tables() {

	basePoint := &point{
		xyz: [12]uint64{
			0xd7362e5a487e2097, 0x231e295329bc66db, 0x979f48c033fd129c, 0x9981e643e9089f48,
			0xb15ea6d2d3dbabe2, 0x8dfc5d5d1f1dc64d, 0x70b6b59aac19c136, 0xcf3f851fd4a582d6,
			0x1000003d1, 0x0, 0x0, 0x0,
		},
	}
	p256k1NAF9Tables = p256k1Curve.generateNAF9Tables(basePoint)
}

func p256k1BaseMulNAF9(p *point, scalar []uint64) {
	//precomputeOnce.Do(initTable)

	wvalue := (scalar[0] << 1) & 0x3ff
	sel, sign := boothW9(uint(wvalue))
	//sm2CurveSelectBaseBeta(p.xyz[0:8], sm2Curve37WindowsTables[0][0:], sel)
	copy(p.xyz[0:8], p256k1NAF9Tables[0][sel*8:])
	if sign != 0 {
		p256k1Neg(p.xyz[4:8])
	}

	// (This is one, in the Montgomery domain.)
	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0x0
	p.xyz[10] = 0x0
	p.xyz[11] = 0x0

	t0 := make([]uint64, 8)

	index := uint(8)
	zero := sel
	//var t1 p256Point
	for i := 1; i < 29; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x3ff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x3ff
		}
		index += 9
		sel, sign = boothW9(uint(wvalue))
		copy(t0[0:8], p256k1NAF9Tables[i][sel*8:])
		//sm2CurveSelectBaseBeta(t0.xyz[0:8], sm2Curve37WindowsTables[i][0:], sel)
		if zero == 0 {
			if sign == 1 {
				p256k1Neg(t0[4:8])
			}
			copy(p.xyz[:], t0[0:8])
			p.xyz[8] = 0x1000003d1
			p.xyz[9] = 0
			p.xyz[10] = 0
			p.xyz[11] = 0
			//fmt.Println("happen 1")
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		//p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign, sel, zero)
		zero |= sel
	}
}
