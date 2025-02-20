package secp256k1

import (
	"math/big"
	"sync"
)

var zero32 []byte = make([]byte, 32)

func (p *point) p256k1PolynomialDalek(points []point, scalarList [][]byte) bool {
	num := len(scalarList)
	tables := make([][]point, num)
	nafList := make([][257]int8, num)
	scalar := make([]byte, 32)
	for i := 0; i < num; i++ {
		tables[i] = make([]point, 8)
		var p2 point
		p256k1PointDoubleAsm(p2.xyz[:], points[i].xyz[:])
		copy(tables[i][0].xyz[:], points[i].xyz[:])
		for j := 1; j < 8; j++ {
			p256k1PointAddAsm(tables[i][j].xyz[:], tables[i][j-1].xyz[:], p2.xyz[:])
		}
		diff := 32 - len(scalarList[i])
		copy(scalar[diff:], scalarList[i])
		copy(scalar[:diff], zero32[:diff])
		nafList[i] = nonAdjacentFormBE256(scalar, 5)
	}
	var tmp point
	zero := true
	for i := 256; i >= 0; i-- {
		if !zero {
			p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		}
		for n := 0; n < num; n++ {
			v := nafList[n][i]
			if v > 0 {
				if zero {
					copy(p.xyz[:], tables[n][v/2].xyz[:])
					zero = false
				} else {
					sign := p256k1PointAddAsm(p.xyz[:], p.xyz[:], tables[n][v/2].xyz[:])
					if sign == 3 {
						p256k1PointDoubleAsm(p.xyz[:], tables[n][v/2].xyz[:])
					} else if sign == 2 {
						zero = true
					}
				}
			} else if v < 0 {
				if zero {
					copy(p.xyz[:], tables[n][-v/2].xyz[:])
					zero = false
				} else {
					copy(tmp.xyz[:], tables[n][-v/2].xyz[:])
					p256k1Neg(tmp.xyz[4:8])
					sign := p256k1PointAddAsm(p.xyz[:], p.xyz[:], tmp.xyz[:])
					if sign == 3 {
						p256k1PointDoubleAsm(p.xyz[:], tmp.xyz[:])
					} else if sign == 2 {
						zero = true
					}
				}
			}
		}

	}
	if zero {
		for i := 0; i < 12; i++ {
			p.xyz[i] = 0
		}
	}

	return !zero
}

func (p *point) ScalarMultDalek(scalar []byte) {
	points := make([]point, 8)
	var p2 point
	p256k1PointDoubleAsm(p2.xyz[:], p.xyz[:])
	copy(points[0].xyz[:], p.xyz[:])
	for i := 1; i < 8; i++ {
		p256k1PointAddAsm(points[i].xyz[:], points[i-1].xyz[:], p2.xyz[:])
	}

	sNaf := nonAdjacentFormBE256(scalar, 5)

	i := 256
	for ; i >= 0; i-- {
		if sNaf[i] != 0 {
			break
		}
	}
	copy(p.xyz[:], points[sNaf[i]/2].xyz[:])
	i--

	var tmp point
	for ; i >= 0; i-- {
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		v := sNaf[i]
		if v > 0 {
			p256k1PointAddAsm(p.xyz[:], p.xyz[:], points[v/2].xyz[:])
		} else if v < 0 {
			copy(tmp.xyz[:], points[-v/2].xyz[:])
			p256k1Neg(tmp.xyz[4:8])
			p256k1PointAddAsm(p.xyz[:], p.xyz[:], tmp.xyz[:])
		}
	}
}

func (c *curve) PolynomialDalek(xList []*big.Int, yList []*big.Int, scalarList [][]byte) (x, y *big.Int) {
	num := len(scalarList)
	points := make([]point, num)
	for i := range points {
		fromBig(points[i].xyz[0:4], maybeReduceModP(xList[i]))
		fromBig(points[i].xyz[4:8], maybeReduceModP(yList[i]))
		p256k1Mul(points[i].xyz[0:4], points[i].xyz[0:4], rr[:])
		p256k1Mul(points[i].xyz[4:8], points[i].xyz[4:8], rr[:])
		points[i].xyz[8] = 0x1000003d1
		points[i].xyz[9] = 0
		points[i].xyz[10] = 0
		points[i].xyz[11] = 0
	}
	r := new(point)
	//r.PolynomialKoblitz(points, scalarList)

	nonZero := r.p256k1PolynomialDalek(points, scalarList)
	if nonZero {
		return r.p256k1PointToAffine()
	} else {
		return big.NewInt(0), big.NewInt(0)
	}
}

func (c *curve) PolynomialDalekX(xList []*big.Int, yList []*big.Int, scalarList [][]byte, core int) (x, y *big.Int) {
	if core < 2 {
		return c.PolynomialDalek(xList, yList, scalarList)
	}
	num := len(scalarList)
	points := make([]point, num)
	var wg sync.WaitGroup
	r := make([]point, core)
	nz := make([]bool, core)
	for t := 0; t < core; t++ {
		s := num * t / core
		e := num * (t + 1) / core
		wg.Add(1)
		go func(start, end, index int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				fromBig(points[i].xyz[0:4], maybeReduceModP(xList[i]))
				fromBig(points[i].xyz[4:8], maybeReduceModP(yList[i]))
				p256k1Mul(points[i].xyz[0:4], points[i].xyz[0:4], rr[:])
				p256k1Mul(points[i].xyz[4:8], points[i].xyz[4:8], rr[:])
				points[i].xyz[8] = 0x1000003d1
				points[i].xyz[9] = 0
				points[i].xyz[10] = 0
				points[i].xyz[11] = 0
			}
			nz[index] = r[index].p256k1PolynomialDalek(points[start:end], scalarList[start:end])

		}(s, e, t)

	}
	wg.Wait()

	zero := !nz[0]
	for i := 1; i < core; i++ {
		if zero {
			copy(r[0].xyz[:], r[i].xyz[:])
		} else {
			if nz[i] {
				eq := p256k1PointAddAsm(r[0].xyz[:], r[0].xyz[:], r[i].xyz[:])
				if eq == 1 {
					p256k1PointDoubleAsm(r[0].xyz[:], r[i].xyz[:])
				}
			}
		}
		if nz[i] {
			zero = false
		}
	}

	return r[0].p256k1PointToAffine()
}
