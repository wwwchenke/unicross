package secp256k1

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestAaron(t *testing.T) {
	InitNAFTables(9)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	d, err := rand.Int(rand.Reader, n1)
	if err != nil {
		t.Fatal(err)
	}
	x, y := p256k1Curve.ScalarBaseMult(d.Bytes())
	k, err := rand.Int(rand.Reader, n1)
	if err != nil {
		t.Fatal(err)
	}

	var r3 point
	fromBig(r3.xyz[0:4], maybeReduceModP(x))
	fromBig(r3.xyz[4:8], maybeReduceModP(y))
	p256k1Mul(r3.xyz[0:4], r3.xyz[0:4], rr[:])
	p256k1Mul(r3.xyz[4:8], r3.xyz[4:8], rr[:])
	// This sets r2's Z value to 1, in the Montgomery domain.
	r3.xyz[8] = 0x1000003d1
	r3.xyz[9] = 0
	r3.xyz[10] = 0
	r3.xyz[11] = 0

	var r point
	fromBig(r.xyz[0:4], maybeReduceModP(x))
	fromBig(r.xyz[4:8], maybeReduceModP(y))
	p256k1Mul(r.xyz[0:4], r.xyz[0:4], rr[:])
	p256k1Mul(r.xyz[4:8], r.xyz[4:8], rr[:])
	// This sets r2's Z value to 1, in the Montgomery domain.
	r.xyz[8] = 0x1000003d1
	r.xyz[9] = 0
	r.xyz[10] = 0
	r.xyz[11] = 0

	var r2 point
	fromBig(r2.xyz[0:4], maybeReduceModP(x))
	fromBig(r2.xyz[4:8], maybeReduceModP(y))
	p256k1Mul(r2.xyz[0:4], r2.xyz[0:4], rr[:])
	p256k1Mul(r2.xyz[4:8], r2.xyz[4:8], rr[:])
	// This sets r2's Z value to 1, in the Montgomery domain.
	r2.xyz[8] = 0x1000003d1
	r2.xyz[9] = 0
	r2.xyz[10] = 0
	r2.xyz[11] = 0
	start := time.Now()
	for i := 0; i < 100000; i++ {
		r.ScalarMultKoblitz(k.Bytes())
	}
	fmt.Println(time.Since(start))

	start = time.Now()
	for i := 0; i < 100000; i++ {
		r2.ScalarMultDalek(k.Bytes())
	}
	fmt.Println(time.Since(start))

	start = time.Now()
	for i := 0; i < 100000; i++ {
		s := make([]uint64, 4)
		sm2CurveGetScalar(s, k.Bytes())
		r3.p256k1ScalarMult(s)
	}
	fmt.Println(time.Since(start))
	//r.p256k1ScalarMult(scalarReversed)
	ax, ay := r.p256k1PointToAffine()
	bx, by := r2.p256k1PointToAffine()
	cx, cy := r3.p256k1PointToAffine()
	fmt.Println(ax.Text(16))
	fmt.Println(ay.Text(16))
	fmt.Println("---------------------------")
	fmt.Println(bx.Text(16))
	fmt.Println(by.Text(16))
	fmt.Println("---------------------------")
	fmt.Println(cx.Text(16))
	fmt.Println(cy.Text(16))

}

func TestSumMultiMul(t *testing.T) {
	InitNAFTables(9)
	num := 65536

	kList := make([][]byte, num)
	xList := make([]*big.Int, num)
	yList := make([]*big.Int, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		xList[i], yList[i] = p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(xList[i], yList[i]) {
			panic("Not on curve")
		}
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		kList[i] = k.Bytes()
	}
	start := time.Now()
	points := make([]point, num)
	resultX := make([]*big.Int, num)
	resultY := make([]*big.Int, num)
	var sum point
	for i := 0; i < num; i++ {
		fromBig(points[i].xyz[0:4], maybeReduceModP(xList[i]))
		fromBig(points[i].xyz[4:8], maybeReduceModP(yList[i]))
		p256k1Mul(points[i].xyz[0:4], points[i].xyz[0:4], rr[:])
		p256k1Mul(points[i].xyz[4:8], points[i].xyz[4:8], rr[:])
		// This sets r2's Z value to 1, in the Montgomery domain.
		points[i].xyz[8] = 0x1000003d1
		points[i].xyz[9] = 0
		points[i].xyz[10] = 0
		points[i].xyz[11] = 0
		points[i].ScalarMultKoblitz(kList[i])
		resultX[i], resultY[i] = points[i].p256k1PointToAffine()
	}
	zero := true
	for i := 0; i < num; i++ {
		if zero {
			copy(sum.xyz[:], points[i].xyz[:])
			zero = false
			continue
		}
		a := p256k1PointAddAsm(sum.xyz[:], sum.xyz[:], points[i].xyz[:])
		if a == 3 {
			p256k1PointDoubleAsm(sum.xyz[:], points[i].xyz[:])
		} else if a == 2 {
			zero = true
		}
	}
	sum.p256k1PointToAffine()

	fmt.Println(time.Since(start))
}

func TestSumMultiMulX(t *testing.T) {
	InitNAFTables(9)
	num := 65536

	kList := make([][]byte, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	xList := make([]*big.Int, num)
	yList := make([]*big.Int, num)
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		xList[i], yList[i] = p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(xList[i], yList[i]) {
			panic("Not on curve")
		}
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		kList[i] = k.Bytes()
	}
	resultX := make([]*big.Int, num)
	resultY := make([]*big.Int, num)
	coreNum := 16
	start := time.Now()
	points := make([]point, num)
	sum := make([]point, coreNum)

	var wg sync.WaitGroup

	for x := 0; x < coreNum; x++ {
		s := num * x / coreNum
		e := num * (x + 1) / coreNum
		wg.Add(1)
		go func(start, end, index int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				fromBig(points[i].xyz[0:4], maybeReduceModP(xList[i]))
				fromBig(points[i].xyz[4:8], maybeReduceModP(yList[i]))
				p256k1Mul(points[i].xyz[0:4], points[i].xyz[0:4], rr[:])
				p256k1Mul(points[i].xyz[4:8], points[i].xyz[4:8], rr[:])
				// This sets r2's Z value to 1, in the Montgomery domain.
				points[i].xyz[8] = 0x1000003d1
				points[i].xyz[9] = 0
				points[i].xyz[10] = 0
				points[i].xyz[11] = 0

				points[i].ScalarMultKoblitz(kList[i])
				resultX[i], resultY[i] = points[i].p256k1PointToAffine()
			}
			zero := true
			for i := start; i < end; i++ {
				if zero {
					copy(sum[index].xyz[:], points[i].xyz[:])
					zero = false
					continue
				}
				a := p256k1PointAddAsm(sum[index].xyz[:], sum[index].xyz[:], points[i].xyz[:])
				if a == 3 {
					p256k1PointDoubleAsm(sum[index].xyz[:], points[i].xyz[:])
				} else if a == 2 {
					zero = true
				}
			}
		}(s, e, x)
	}
	wg.Wait()
	zero := true
	var final point
	for i := 0; i < coreNum; i++ {
		if zero {
			copy(final.xyz[:], sum[i].xyz[:])
			zero = false
			continue
		}
		a := p256k1PointAddAsm(final.xyz[:], final.xyz[:], sum[i].xyz[:])
		if a == 3 {
			p256k1PointDoubleAsm(final.xyz[:], sum[i].xyz[:])
		} else if a == 2 {
			zero = true
		}
	}

	fmt.Println(time.Since(start))
}

func TestCurvePoly(t *testing.T) {
	InitNAFTables(9)
	num := 65536
	xList := make([]*big.Int, num)
	yList := make([]*big.Int, num)
	kList := make([][]byte, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		xList[i], yList[i] = p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(xList[i], yList[i]) {
			panic("Not on curve")
		}
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		kList[i] = k.Bytes()
	}
	start := time.Now()
	rx, ry := p256k1Curve.ScalarMult(xList[0], yList[0], kList[0])
	for i := 1; i < num; i++ {
		x, y := p256k1Curve.ScalarMult(xList[i], yList[i], kList[i])
		rx, ry = p256k1Curve.Add(rx, ry, x, y)
	}
	fmt.Println(rx.Text(10))
	fmt.Println(ry.Text(10))
	fmt.Println(time.Since(start))
	start = time.Now()
	rx2, ry2 := p256k1Curve.PolynomialDalekX(xList, yList, kList, 16)
	fmt.Println(rx2.Text(10))
	fmt.Println(ry2.Text(10))
	fmt.Println(time.Since(start))

}
