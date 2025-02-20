package secp256k1

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"sync"
)

var (
	p256k1Curve *curve = &curve{
		params: new(elliptic.CurveParams),
	}
	rr                   = []uint64{0x000007a2000e90a1, 0x1, 0, 0}
	ro                   = []uint64{0x896cf21467d7d140, 0x741496c20e7cf878, 0xe697f5e45bcd07c6, 0x9d671cd581c69bc5}
	a1, a2, b1, b2, beta *big.Int
	betaField            = []uint64{0x58a4361c8e81894e, 0x3fde1631c4b80af, 0xf8e98978d02e3905, 0x7a4a36aebcbb3d53}
	closedChannel        chan int
)

type curve struct {
	params *elliptic.CurveParams
}

type VSCurve interface {
	elliptic.Curve
	ComputePrecomputesForPoint(x, y *big.Int) interface{}
	ScalarMultByPrecomputes(scalar []byte, precomputes interface{}) (x, y *big.Int)
}

type point struct {
	xyz [12]uint64
}

func Curve() VSCurve {
	return p256k1Curve
}

func initP256K1Curve() {
	p256k1Curve.params.Name = "secp256k1"
	p256k1Curve.params.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	p256k1Curve.params.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	p256k1Curve.params.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	p256k1Curve.params.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	p256k1Curve.params.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	p256k1Curve.params.BitSize = 256

	a1, _ = new(big.Int).SetString("3086D221A7D46BCDE86C90E49284EB15", 16)
	b1, _ = new(big.Int).SetString("-E4437ED6010E88286F547FA90ABFE4C3", 16)
	a2, _ = new(big.Int).SetString("114CA50F7A8E2F3F657C1108D9D44CFD8", 16)
	b2, _ = new(big.Int).SetString("3086D221A7D46BCDE86C90E49284EB15", 16)
	beta, _ = new(big.Int).SetString("7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE", 16)
	closedChannel = make(chan int)
	close(closedChannel)
}

func (c *curve) Params() *elliptic.CurveParams {
	return c.params
}

func (c *curve) IsOnCurve(x, y *big.Int) bool {
	p := c.params.P
	if x.Sign() < 0 || x.Cmp(p) >= 0 ||
		y.Sign() < 0 || y.Cmp(p) >= 0 {
		return false
	}

	// y² = x³ + b
	left := new(big.Int).Mul(y, y)
	left.Mod(left, p)
	x2 := new(big.Int).Mul(x, x)
	x3 := new(big.Int).Mul(x2, x)
	right := new(big.Int).Add(x3, c.params.B)
	right.Mod(right, p)

	return left.Cmp(right) == 0
}

func (c *curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if y1.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).SetBytes(x2.Bytes()), new(big.Int).SetBytes(y2.Bytes())
	}
	if y2.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).SetBytes(x1.Bytes()), new(big.Int).SetBytes(y1.Bytes())
	}

	var p1, p2 point
	fromBig(p1.xyz[0:4], x1)
	fromBig(p1.xyz[4:8], y1)
	p256k1Mul(p1.xyz[0:4], p1.xyz[0:4], rr)
	p256k1Mul(p1.xyz[4:8], p1.xyz[4:8], rr)
	p1.xyz[8] = 0x1000003d1
	p1.xyz[9] = 0
	p1.xyz[10] = 0
	p1.xyz[11] = 0

	fromBig(p2.xyz[0:4], x2)
	fromBig(p2.xyz[4:8], y2)
	p256k1Mul(p2.xyz[0:4], p2.xyz[0:4], rr)
	p256k1Mul(p2.xyz[4:8], p2.xyz[4:8], rr)
	p2.xyz[8] = 0x1000003d1
	p2.xyz[9] = 0
	p2.xyz[10] = 0
	p2.xyz[11] = 0
	p256k1PointAddAffineAsm(p1.xyz[:], p1.xyz[:], p2.xyz[:], 0)
	x, y = p1.p256k1PointToAffine()
	return
}

// Double returns 2*(x,y)
func (c *curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	if y1.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	var p point
	fromBig(p.xyz[0:4], x1)
	fromBig(p.xyz[4:8], y1)
	p256k1Mul(p.xyz[0:4], p.xyz[0:4], rr)
	p256k1Mul(p.xyz[4:8], p.xyz[4:8], rr)
	p.xyz[8] = 0x1000003d1
	p.xyz[9] = 0
	p.xyz[10] = 0
	p.xyz[11] = 0
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	x, y = p.p256k1PointToAffine()
	return
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (c *curve) ScalarMult(bigX, bigY *big.Int, scalar []byte) (x, y *big.Int) {
	//scalarReversed := make([]uint64, 4)
	//sm2CurveGetScalar(scalarReversed, scalar)

	var r point
	fromBig(r.xyz[0:4], maybeReduceModP(bigX))
	fromBig(r.xyz[4:8], maybeReduceModP(bigY))
	p256k1Mul(r.xyz[0:4], r.xyz[0:4], rr[:])
	p256k1Mul(r.xyz[4:8], r.xyz[4:8], rr[:])
	// This sets r2's Z value to 1, in the Montgomery domain.
	r.xyz[8] = 0x1000003d1
	r.xyz[9] = 0
	r.xyz[10] = 0
	r.xyz[11] = 0

	r.ScalarMultKoblitz(scalar)
	//r.p256k1ScalarMult(scalarReversed)
	return r.p256k1PointToAffine()
}

func (c *curve) Polynomial(xList []*big.Int, yList []*big.Int, scalarList [][]byte) (x, y *big.Int) {
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
	scalarReversed := make([][]uint64, len(scalarList))
	for i, scalar := range scalarList {
		scalarReversed[i] = make([]uint64, 4)
		sm2CurveGetScalar(scalarReversed[i], scalar)
	}
	nonZero := r.p256k1Polynomial(points, scalarReversed)
	if nonZero {
		return r.p256k1PointToAffine()
	} else {
		return big.NewInt(0), big.NewInt(0)
	}
}

func (c *curve) PolynomialX(xList []*big.Int, yList []*big.Int, scalarList [][]byte, core int) (x, y *big.Int) {
	if core < 2 {
		return c.Polynomial(xList, yList, scalarList)
	}
	num := len(scalarList)
	points := make([]point, num)
	scalarReversed := make([][]uint64, len(scalarList))
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
			for i := start; i < end; i++ {
				scalarReversed[i] = make([]uint64, 4)
				sm2CurveGetScalar(scalarReversed[i], scalarList[i])
			}
			nz[index] = r[index].p256k1Polynomial(points[start:end], scalarReversed[start:end])

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

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (c *curve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	sm2CurveGetScalar(scalarReversed, scalar)

	var r point
	p256k1BaseMul(&r, scalarReversed)
	return r.p256k1PointToAffine()
}

// p256k1PointToAffine converts a Jacobian point to an affine point. If the input
// is the point at infinity then it returns (0, 0) in constant time.
func (p *point) p256k1PointToAffine() (x, y *big.Int) {
	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	p256k1Inverse(zInv, p.xyz[8:12])
	p256k1Sqr(zInvSq, zInv, 1)
	p256k1Mul(zInv, zInv, zInvSq)

	p256k1Mul(zInvSq, p.xyz[0:4], zInvSq)
	p256k1Mul(zInv, p.xyz[4:8], zInv)

	p256k1FromMont(zInvSq, zInvSq)
	p256k1FromMont(zInv, zInv)

	xOut := make([]byte, 32)
	yOut := make([]byte, 32)
	p256k1LittleToBig(xOut, zInvSq)
	p256k1LittleToBig(yOut, zInv)

	return new(big.Int).SetBytes(xOut), new(big.Int).SetBytes(yOut)
}

// simple implementation of inverse, faster than constant-time fermat method
func p256k1Inverse(out, in []uint64) {
	//inBytes := make([]byte, 32)
	//p256k1LittleToBig(inBytes, in)
	//n := new(big.Int).SetBytes(inBytes)
	//n.ModInverse(n, p256k1Curve.params.P)
	//fromBig(out, n)
	//p256k1Mul(out, out, rrr)
	p256k1FromMont(out, in)
	var k uint64
	p256k1MontInversePhase1(out, out, &k)
	if k == 256 {
		return
	}
	k = 512 - k
	exField := make([]uint64, 4)
	exField[k/64] = 1 << (k % 64)
	p256k1Mul(out, out, exField)
}

func init() {
	initP256K1Curve()
	//init37WindowsTables()
}

var p256k1BaseMul func(*point, []uint64)

func InitNAFTables(w int) {
	p256k1NAF6Tables = nil
	p256k1NAF7Tables = nil
	p256k1NAF8Tables = nil
	p256k1NAF9Tables = nil
	if w == 6 {
		initNAF6Tables()
		p256k1BaseMul = p256k1BaseMulNAF6
	} else if w == 7 {
		initNAF7Tables()
		p256k1BaseMul = p256k1BaseMulNAF7
	} else if w == 8 {
		initNAF8Tables()
		p256k1BaseMul = p256k1BaseMulNAF8
	} else if w == 9 {
		initNAF9Tables()
		p256k1BaseMul = p256k1BaseMulNAF9
	} else {
		panic(fmt.Sprintf("Unsupported NAF number %d", w))
	}
}

func (p *point) p256StorePoint(r *[17 * 4 * 3]uint64, index int) {
	copy(r[index*12:], p.xyz[:])
}

func (p *point) p256k1Polynomial(points []point, scalarList [][]uint64) bool {
	num := len(scalarList)
	tableList := make([]*[17 * 12]uint64, num)
	var t0, t1, t2, t3 point
	for i := 0; i < num; i++ {
		tables := new([17 * 12]uint64)
		points[i].p256StorePoint(tables, 1)
		p256k1PointDoubleAsm(t0.xyz[:], points[i].xyz[:])
		p256k1PointDoubleAsm(t1.xyz[:], t0.xyz[:])
		p256k1PointDoubleAsm(t2.xyz[:], t1.xyz[:])
		p256k1PointDoubleAsm(t3.xyz[:], t2.xyz[:])
		t0.p256StorePoint(tables, 2)  // 2
		t1.p256StorePoint(tables, 4)  // 4
		t2.p256StorePoint(tables, 8)  // 8
		t3.p256StorePoint(tables, 16) // 16

		p256k1PointAddAffineAsm(t0.xyz[:], t0.xyz[:], points[i].xyz[:], 0)
		p256k1PointAddAffineAsm(t1.xyz[:], t1.xyz[:], points[i].xyz[:], 0)
		p256k1PointAddAffineAsm(t2.xyz[:], t2.xyz[:], points[i].xyz[:], 0)
		t0.p256StorePoint(tables, 3) // 3
		t1.p256StorePoint(tables, 5) // 5
		t2.p256StorePoint(tables, 9) // 9

		p256k1PointDoubleAsm(t0.xyz[:], t0.xyz[:])
		p256k1PointDoubleAsm(t1.xyz[:], t1.xyz[:])
		t0.p256StorePoint(tables, 6)  // 6
		t1.p256StorePoint(tables, 10) // 10

		p256k1PointAddAffineAsm(t2.xyz[:], t0.xyz[:], points[i].xyz[:], 0)
		p256k1PointAddAffineAsm(t1.xyz[:], t1.xyz[:], points[i].xyz[:], 0)
		t2.p256StorePoint(tables, 7)  // 7
		t1.p256StorePoint(tables, 11) // 11

		p256k1PointDoubleAsm(t0.xyz[:], t0.xyz[:])
		p256k1PointDoubleAsm(t2.xyz[:], t2.xyz[:])
		t0.p256StorePoint(tables, 12) // 12
		t2.p256StorePoint(tables, 14) // 14

		p256k1PointAddAffineAsm(t0.xyz[:], t0.xyz[:], points[i].xyz[:], 0)
		p256k1PointAddAffineAsm(t2.xyz[:], t2.xyz[:], points[i].xyz[:], 0)
		t0.p256StorePoint(tables, 13) // 13
		t2.p256StorePoint(tables, 15) // 15

		tableList[i] = tables
	}
	index := uint(254)
	var sel, sign int
	var value uint64

	zero := 0
	for i := 0; i < num; i++ {
		value = (scalarList[i][index/64] >> (index % 64)) & 0x3f
		sel, _ = boothW5(uint(value))

		if sel != 0 {
			if zero == 0 {
				copy(p.xyz[:], tableList[i][sel*12:])
				zero = 1
			} else {
				a := p256k1PointAddAsm(p.xyz[:], p.xyz[:], tableList[i][sel*12:])
				if a == 3 {
					p256k1PointDoubleAsm(p.xyz[:], tableList[i][sel*12:])
				}
				if a == 2 {
					zero = 0
				}
			}
		}
	}

	for index > 4 {
		index -= 5
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])

		for i := 0; i < num; i++ {
			if index < 192 {
				value = ((scalarList[i][index/64] >> (index % 64)) + (scalarList[i][index/64+1] << (64 - (index % 64)))) & 0x3f
			} else {
				value = (scalarList[i][index/64] >> (index % 64)) & 0x3f
			}
			sel, sign = boothW5(uint(value))
			if sel != 0 {
				copy(t0.xyz[:], tableList[i][sel*12:])
				if sign != 0 {
					p256k1Neg(t0.xyz[4:8])
				}
				if zero == 0 {
					copy(p.xyz[:], t0.xyz[:])
					zero = 1
				} else {
					a := p256k1PointAddAsm(p.xyz[:], p.xyz[:], t0.xyz[:])
					if a == 3 {
						p256k1PointDoubleAsm(p.xyz[:], t0.xyz[:])
					} else if a == 2 {
						zero = 0
					}
				}
			}
		}
	}
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])

	for i := 0; i < num; i++ {
		value = (scalarList[i][0] << 1) & 0x3f
		sel, sign = boothW5(uint(value))
		if sel != 0 {
			copy(t0.xyz[:], tableList[i][sel*12:])
			if sign != 0 {
				p256k1Neg(t0.xyz[4:8])
			}
			if zero == 0 {
				copy(p.xyz[:], t0.xyz[:])
				zero = 1
			} else {
				a := p256k1PointAddAsm(p.xyz[:], p.xyz[:], t0.xyz[:])
				if a == 3 {
					p256k1PointDoubleAsm(p.xyz[:], t0.xyz[:])
				} else if a == 2 {
					zero = 0
				}
			}
		}
		zero |= sel
	}

	if zero == 0 {
		for i := 0; i < 12; i++ {
			p.xyz[i] = 0
		}
		return false
	}
	return true
}

func (p *point) p256k1ScalarMult(scalar []uint64) {
	// tables is a table of precomputed points that stores powers of p
	// from p^1 to p^16.
	var t0, t1, t2, t3 point

	tables := new([17 * 12]uint64)

	// Prepare the table
	p.p256StorePoint(tables, 1) // 1

	p256k1PointDoubleAsm(t0.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(t1.xyz[:], t0.xyz[:])
	p256k1PointDoubleAsm(t2.xyz[:], t1.xyz[:])
	p256k1PointDoubleAsm(t3.xyz[:], t2.xyz[:])
	t0.p256StorePoint(tables, 2)  // 2
	t1.p256StorePoint(tables, 4)  // 4
	t2.p256StorePoint(tables, 8)  // 8
	t3.p256StorePoint(tables, 16) // 16

	p256k1PointAddAffineAsm(t0.xyz[:], t0.xyz[:], p.xyz[:], 0)
	p256k1PointAddAffineAsm(t1.xyz[:], t1.xyz[:], p.xyz[:], 0)
	p256k1PointAddAffineAsm(t2.xyz[:], t2.xyz[:], p.xyz[:], 0)
	//p256k1PointAddAsm(t0.xyz[:], t0.xyz[:], p.xyz[:])
	//p256k1PointAddAsm(t1.xyz[:], t1.xyz[:], p.xyz[:])
	//p256k1PointAddAsm(t2.xyz[:], t2.xyz[:], p.xyz[:])

	t0.p256StorePoint(tables, 3) // 3
	t1.p256StorePoint(tables, 5) // 5
	t2.p256StorePoint(tables, 9) // 9

	p256k1PointDoubleAsm(t0.xyz[:], t0.xyz[:])
	p256k1PointDoubleAsm(t1.xyz[:], t1.xyz[:])
	t0.p256StorePoint(tables, 6)  // 6
	t1.p256StorePoint(tables, 10) // 10

	p256k1PointAddAffineAsm(t2.xyz[:], t0.xyz[:], p.xyz[:], 0)
	p256k1PointAddAffineAsm(t1.xyz[:], t1.xyz[:], p.xyz[:], 0)
	//p256k1PointAddAsm(t2.xyz[:], t0.xyz[:], p.xyz[:])
	//p256k1PointAddAsm(t1.xyz[:], t1.xyz[:], p.xyz[:])
	t2.p256StorePoint(tables, 7)  // 7
	t1.p256StorePoint(tables, 11) // 11

	p256k1PointDoubleAsm(t0.xyz[:], t0.xyz[:])
	p256k1PointDoubleAsm(t2.xyz[:], t2.xyz[:])
	t0.p256StorePoint(tables, 12) // 12
	t2.p256StorePoint(tables, 14) // 14

	p256k1PointAddAffineAsm(t0.xyz[:], t0.xyz[:], p.xyz[:], 0)
	p256k1PointAddAffineAsm(t2.xyz[:], t2.xyz[:], p.xyz[:], 0)
	//p256k1PointAddAsm(t0.xyz[:], t0.xyz[:], p.xyz[:])
	//p256k1PointAddAsm(t2.xyz[:], t2.xyz[:], p.xyz[:])
	t0.p256StorePoint(tables, 13) // 13
	t2.p256StorePoint(tables, 15) // 15

	// Start scanning the window from top bit
	index := uint(254)
	var sel, sign int

	wvalue := (scalar[index/64] >> (index % 64)) & 0x3f
	sel, _ = boothW5(uint(wvalue))

	//sm2CurveSelectBeta(p.xyz[0:12], tables[0:], sel)
	copy(p.xyz[0:12], tables[sel*12:])
	zero := sel

	for index > 4 {
		index -= 5
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
		p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])

		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x3f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x3f
		}

		sel, sign = boothW5(uint(wvalue))

		//copy(t0.xyz[0:], tables[sel*12:sel*12+12])
		//sm2CurveSelectBeta(t0.xyz[0:], tables[0:], sel)
		copy(t0.xyz[:], tables[sel*12:])
		if sign != 0 {
			p256k1Neg(t0.xyz[4:8])
		}
		p256k1PointAddAsm(t1.xyz[:], p.xyz[:], t0.xyz[:])
		if sel == 0 {
			copy(t1.xyz[:], p.xyz[:])
		}
		//p256k1MovCond(t1.xyz[0:12], t1.xyz[0:12], p.xyz[0:12], sel)
		if zero != 0 {
			copy(p.xyz[:], t1.xyz[:])
		} else {
			copy(p.xyz[:], t0.xyz[:])
		}
		//p256k1MovCond(p.xyz[0:12], t1.xyz[0:12], t0.xyz[0:12], zero)
		zero |= sel
	}

	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])
	p256k1PointDoubleAsm(p.xyz[:], p.xyz[:])

	wvalue = (scalar[0] << 1) & 0x3f
	sel, sign = boothW5(uint(wvalue))

	copy(t0.xyz[0:], tables[sel*12:])
	//sm2CurveSelectBeta(t0.xyz[0:], tables[0:], sel)
	if sign != 0 {
		p256k1Neg(t0.xyz[4:8])
	}
	p256k1PointAddAsm(t1.xyz[:], p.xyz[:], t0.xyz[:])
	if sel == 0 {
		copy(t1.xyz[:], p.xyz[:])
	}
	//p256k1MovCond(t1.xyz[0:12], t1.xyz[0:12], p.xyz[0:12], sel)
	if zero != 0 {
		copy(p.xyz[:], t1.xyz[:])
	} else {
		copy(p.xyz[:], t0.xyz[:])
	}
	//p256k1MovCond(p.xyz[0:12], t1.xyz[0:12], t0.xyz[0:12], zero)
}

func (c *curve) ScalarMultByPrecomputes(scalar []byte, precomputes interface{}) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	sm2CurveGetScalar(scalarReversed, scalar)

	var r point
	if tables, ok := precomputes.(*[43][33 * 8]uint64); ok {
		r.p256k1ScalarMultByPrecomputesNAF6(scalarReversed, tables)
		return r.p256k1PointToAffine()
	}
	if tables, ok := precomputes.(*[37][65 * 8]uint64); ok {
		r.p256k1ScalarMultByPrecomputesNAF7(scalarReversed, tables)
		return r.p256k1PointToAffine()
	}
	if tables, ok := precomputes.(*[33][129 * 8]uint64); ok {
		r.p256k1ScalarMultByPrecomputesNAF8(scalarReversed, tables)
		return r.p256k1PointToAffine()
	}
	if tables, ok := precomputes.(*[29][257 * 8]uint64); ok {
		r.p256k1ScalarMultByPrecomputesNAF9(scalarReversed, tables)
		return r.p256k1PointToAffine()
	}
	panic("Unsupported precomputes")
}

func (p *point) p256k1ScalarMultByPrecomputesNAF7(scalar []uint64, tables *[37][65 * 8]uint64) {
	wvalue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wvalue))
	copy(p.xyz[0:8], tables[0][sel*8:])
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
		copy(t0[0:8], tables[i][sel*8:])
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
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		zero |= sel
	}
}

func (p *point) p256k1ScalarMultByPrecomputesNAF6(scalar []uint64, tables *[43][33 * 8]uint64) {
	wvalue := (scalar[0] << 1) & 0x7f
	sel, sign := boothW6(uint(wvalue))
	copy(p.xyz[0:8], tables[0][sel*8:])
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
		copy(t0[0:8], tables[i][sel*8:])
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
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		zero |= sel
	}
}

func (p *point) p256k1ScalarMultByPrecomputesNAF8(scalar []uint64, tables *[33][129 * 8]uint64) {
	wvalue := (scalar[0] << 1) & 0x1ff
	sel, sign := boothW8(uint(wvalue))
	copy(p.xyz[0:8], tables[0][sel*8:])
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
		copy(t0[0:8], tables[i][sel*8:])
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
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		zero |= sel
	}
}

func (p *point) p256k1ScalarMultByPrecomputesNAF9(scalar []uint64, tables *[29][257 * 8]uint64) {
	wvalue := (scalar[0] << 1) & 0x3ff
	sel, sign := boothW9(uint(wvalue))
	copy(p.xyz[0:8], tables[0][sel*8:])
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
		copy(t0[0:8], tables[i][sel*8:])
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
		} else if sel != 0 {
			p256k1PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0[0:8], sign)
		}
		zero |= sel
	}
}

func ComputePrecomputesForPoint(x, y *big.Int) interface{} {
	return p256k1Curve.ComputePrecomputesForPoint(x, y)
}
