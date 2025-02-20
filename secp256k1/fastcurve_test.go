package secp256k1

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"
	vc "volley/curve"
)

func BenchmarkFastScalarMult(t *testing.B) {
	InitNAFTables(9)
	num := 65536

	kList := make([][]byte, num)
	pList := make([]vc.FastPoint, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		x, y := p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(x, y) {
			panic("Not on curve")
		}
		pList[i] = p256k1Curve.NewPoint()
		pList[i].From(x, y)
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		kList[i] = k.Bytes()
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		p256k1Curve.FastScalarMult(pList[i], pList[i], kList[i])
	}
	t.StopTimer()
}

func TestFastPoly(t *testing.T) {
	InitNAFTables(9)
	num := 65536

	kList := make([][]byte, num)
	pList := make([]vc.FastPoint, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	var sumX, sumY *big.Int
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		x, y := p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(x, y) {
			panic("Not on curve")
		}

		pList[i] = p256k1Curve.NewPoint()
		pList[i].From(x, y)
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		kList[i] = k.Bytes()

		if i > 0 {
			mx, my := p256k1Curve.ScalarMult(x, y, kList[i])
			sumX, sumY = p256k1Curve.Add(sumX, sumY, mx, my)
		} else {
			sumX, sumY = p256k1Curve.ScalarMult(x, y, kList[i])
		}
	}
	r := p256k1Curve.NewPoint()

	p256k1Curve.FastPolynomial(r, pList, kList)

	rx, ry := r.Back()
	fmt.Println(rx.Cmp(sumX))
	fmt.Println(ry.Cmp(sumY))
}

func BenchmarkFastPoly(t *testing.B) {
	InitNAFTables(9)
	num := 65536

	kList := make([][]byte, num)
	pList := make([]vc.FastPoint, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	sumX := big.NewInt(0)
	sumY := big.NewInt(0)
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		x, y := p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(x, y) {
			panic("Not on curve")
		}
		pList[i] = p256k1Curve.NewPoint()
		pList[i].From(x, y)
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			t.Fatal(err)
		}
		kList[i] = k.Bytes()
		mx, my := p256k1Curve.ScalarMult(x, y, kList[i])
		sumX, sumY = p256k1Curve.Add(sumX, sumY, mx, my)
	}
	r := p256k1Curve.NewPoint()
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		p256k1Curve.FastPolynomial(r, pList, kList)
	}
	t.StopTimer()
	rx, ry := r.Back()
	fmt.Println(rx.Cmp(sumX))
	fmt.Println(ry.Cmp(sumY))
}

func BenchmarkFastPolyMulti(b *testing.B) {
	InitNAFTables(9)
	num := 65536

	kList := make([][]byte, num)
	pList := make([]vc.FastPoint, num)
	n1 := new(big.Int).Sub(p256k1Curve.Params().N, big.NewInt(1))
	sumX := big.NewInt(0)
	sumY := big.NewInt(0)
	for i := 0; i < num; i++ {
		d, err := rand.Int(rand.Reader, n1)
		if err != nil {
			b.Fatal(err)
		}
		x, y := p256k1Curve.ScalarBaseMult(d.Bytes())
		if !p256k1Curve.IsOnCurve(x, y) {
			panic("Not on curve")
		}
		pList[i] = p256k1Curve.NewPoint()
		pList[i].From(x, y)
		k, err := rand.Int(rand.Reader, n1)
		if err != nil {
			b.Fatal(err)
		}
		kList[i] = k.Bytes()
		mx, my := p256k1Curve.ScalarMult(x, y, kList[i])
		sumX, sumY = p256k1Curve.Add(sumX, sumY, mx, my)
	}
	core := 16
	result := p256k1Curve.NewPoint()
	b.ResetTimer()
	for x := 0; x < b.N; x++ {
		var wg sync.WaitGroup
		r := make([]vc.FastPoint, core)
		for t := 0; t < core; t++ {
			s := num * t / core
			e := num * (t + 1) / core
			wg.Add(1)
			go func(start, end, index int) {
				defer wg.Done()
				r[index] = p256k1Curve.NewPoint()
				p256k1Curve.FastPolynomial(r[index], pList[start:end], kList[start:end])
			}(s, e, t)

		}
		wg.Wait()

		result.CopyFrom(r[0])
		for i := 1; i < core; i++ {
			p256k1Curve.FastPointAdd(result, result, r[i])
		}
	}
	b.StopTimer()
	rx, ry := result.Back()
	fmt.Println(rx.Cmp(sumX))
	fmt.Println(ry.Cmp(sumY))
}

func TestRR(t *testing.T) {
	InitNAFTables(9)
	a, _ := rand.Int(rand.Reader, p256k1Curve.params.N)
	pointA := p256k1Curve.FastBaseScalar(a.Bytes())
	pointA.GenTable(true)

	res := make([]uint64, 12)
	fmt.Println(pointA.(*Point).table[0].xyz[:])
	fmt.Println(p256k1PointAddAsm(res, pointA.(*Point).table[0].xyz[:], pointA.(*Point).table[1].xyz[:]))
	p256k1Neg(pointA.(*Point).table[1].xyz[4:8])
	fmt.Println(p256k1PointAddAsm(res, res, pointA.(*Point).table[1].xyz[:]))
	fmt.Println(res)

}
