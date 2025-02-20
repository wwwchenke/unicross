package protocol_test

import (
	"crypto/rand"
	"math/big"
	"testing"
	vc "volley/curve"
	"volley/lpr"
	"volley/protocol"
	"volley/secp256k1"
)

func BenchmarkSetup(b *testing.B) {
	secp256k1.InitNAFTables(9)
	fastCurve := secp256k1.FastCurve()
	n1 := fastCurve.Params().N
	var k *big.Int
	pointBytes := make([]byte, 64)
	var err error
	L := protocol.L
	random := rand.Reader

	b.ResetTimer()
	for n := 0; n < b.N; n++ {

		for i := int32(0); i < L; i++ {
			k, err = rand.Int(random, n1)
			if err != nil {
				b.Fatal(err)
			}
			point := fastCurve.FastBaseScalar(k.Bytes())
			px, py := point.Back()
			px.FillBytes(pointBytes[0:32])
			py.FillBytes(pointBytes[32:64])
			//point.GenTable(true)
		}

		for i := int32(0); i < L; i++ {
			k, err = rand.Int(random, n1)
			if err != nil {
				b.Fatal(err)
			}
			point := fastCurve.FastBaseScalar(k.Bytes())
			px, py := point.Back()
			px.FillBytes(pointBytes[0:32])
			py.FillBytes(pointBytes[32:64])
		}
		k, err = rand.Int(random, n1)
		if err != nil {
			b.Fatal(err)
		}
		point := fastCurve.FastBaseScalar(k.Bytes())
		px, py := point.Back()
		px.FillBytes(pointBytes[0:32])
		py.FillBytes(pointBytes[32:64])
	}
}

func BenchmarkSetupWithPrecomputes(b *testing.B) {

	secp256k1.InitNAFTables(9)
	fastCurve := secp256k1.FastCurve()
	n1 := fastCurve.Params().N
	var k *big.Int
	pointBytes := make([]byte, 64)
	var err error
	L := protocol.L
	D := protocol.D
	B := protocol.B
	BPrime := protocol.BPrime
	hSum1 := fastCurve.NewPoint()
	hSum2 := fastCurve.NewPoint()

	random := rand.Reader

	b.ResetTimer()
	for n := 0; n < b.N; n++ {

		for i := int32(0); i < L; i++ {
			k, err = rand.Int(random, n1)
			if err != nil {
				b.Fatal(err)
			}
			point := fastCurve.FastBaseScalar(k.Bytes())
			px, py := point.Back()
			px.FillBytes(pointBytes[0:32])
			py.FillBytes(pointBytes[32:64])
			point.ExportTable(true)
			//point.GenTable(true)
		}

		for i := int32(0); i < L; i++ {
			k, err = rand.Int(random, n1)
			if err != nil {
				b.Fatal(err)
			}
			point := fastCurve.FastBaseScalar(k.Bytes())
			px, py := point.Back()
			px.FillBytes(pointBytes[0:32])
			py.FillBytes(pointBytes[32:64])
			point.ExportTable(true)

			if i >= 3*D*B && i < 3*D*B+D*BPrime {
				fastCurve.FastPointAdd(hSum2, hSum2, point)
			} else {
				fastCurve.FastPointAdd(hSum1, hSum1, point)
			}
		}
		k, err = rand.Int(random, n1)
		if err != nil {
			b.Fatal(err)
		}
		point := fastCurve.FastBaseScalar(k.Bytes())
		px, py := point.Back()
		px.FillBytes(pointBytes[0:32])
		py.FillBytes(pointBytes[32:64])

		hx, hy := hSum1.Back()
		hx.FillBytes(pointBytes[0:32])
		hy.FillBytes(pointBytes[32:64])
		hx, hy = hSum2.Back()
		hx.FillBytes(pointBytes[0:32])
		hy.FillBytes(pointBytes[32:64])
	}
}

func initTumbler() (*protocol.Tumbler, vc.FastPoint, vc.FastPoint) {
	secp256k1.InitNAFTables(9)
	fastCurve := secp256k1.FastCurve()
	tumbler := new(protocol.Tumbler)
	n1 := fastCurve.Params().N
	var k *big.Int
	var err error
	L := protocol.L
	D := protocol.D
	B := protocol.B
	B1 := protocol.B1
	Q := protocol.Q
	BPrime := protocol.BPrime
	hSum1 := fastCurve.NewPoint()
	hSum2 := fastCurve.NewPoint()
	G := make([]vc.FastPoint, L)
	H := make([]vc.FastPoint, L)

	random := rand.Reader

	for i := int32(0); i < L; i++ {
		k, err = rand.Int(random, n1)
		if err != nil {
			panic(err)
		}
		G[i] = fastCurve.FastBaseScalar(k.Bytes())
		G[i].GenTable(true)
	}

	for i := int32(0); i < L; i++ {
		k, err = rand.Int(random, n1)
		if err != nil {
			panic(err)
		}
		H[i] = fastCurve.FastBaseScalar(k.Bytes())
		H[i].GenTable(true)

		if i >= 3*D*B && i < 3*D*B+D*BPrime {
			fastCurve.FastPointAdd(hSum2, hSum2, H[i])
		} else {
			fastCurve.FastPointAdd(hSum1, hSum1, H[i])
		}
	}
	k, err = rand.Int(random, n1)
	if err != nil {
		panic(err)
	}
	U := fastCurve.FastBaseScalar(k.Bytes())

	tumbler.G = G
	tumbler.H = H
	tumbler.U = U

	box := make([][]*big.Int, 16)
	for i := 0; i < 16; i++ {
		box[i] = make([]*big.Int, D)
		for j := 0; j < int(D); j++ {
			box[i][j] = big.NewInt(0)
		}
	}

	tmpForBox := make([]*big.Int, 64)
	tmpForBox[0] = big.NewInt(1)
	for i := 1; i < 64; i++ {
		tmpForBox[i] = new(big.Int).Mul(tmpForBox[i-1], big.NewInt(int64(16)))
	}
	for i := 0; i < 16; i++ {
		for j := 0; j < 64; j++ {
			box[i][i*64+j] = new(big.Int).Set(tmpForBox[j])
		}
	}
	boxPrime := make([][]*big.Int, 16)
	for i := 0; i < 16; i++ {
		boxPrime[i] = make([]*big.Int, D*2)
	}
	N := fastCurve.Params().N
	minus2 := new(big.Int).Sub(N, big.NewInt(2))
	for i := 0; i < 16; i++ {
		for j := 0; j < int(D); j++ {
			d1 := new(big.Int).Set(box[i][j])
			d2 := new(big.Int).Mul(box[i][j], minus2)
			d1.Mod(d1, N)
			d2.Mod(d2, N)
			boxPrime[i][j*2] = d1
			boxPrime[i][j*2+1] = d2
		}
	}
	tumbler.Box = boxPrime

	b1List := make([]*big.Int, B1)
	for i := int32(0); i < B1; i++ {
		b1List[i] = big.NewInt(int64(1) << i)
	}
	b1List[B1-1].Sub(N, b1List[B1-1])
	tumbler.B1List = b1List

	tumbler.Secret, err = rand.Int(random, n1)
	if err != nil {
		panic(err)
	}
	tumbler.Public = fastCurve.FastBaseScalar(tumbler.Secret.Bytes())

	tumbler.RLWESecret, err = lpr.GenSecret(D, random)
	if err != nil {
		panic(err)
	}
	tumbler.RLWEPublic, err = lpr.GenPublicKey(tumbler.RLWESecret, Q, random)
	if err != nil {
		panic(err)
	}

	return tumbler, hSum1, hSum2
}

func BenchmarkGenProof(b *testing.B) {
	secp256k1.InitNAFTables(9)
	protocol.SetCurve(secp256k1.FastCurve())
	protocol.SetCoreNum(16)

	random := rand.Reader
	D := protocol.D
	T := protocol.T
	Q := protocol.Q
	YNumber := protocol.YNumber
	tumbler, _, _ := initTumbler()
	plainData, err := lpr.GenerateRq(D, T/2, random)
	if err != nil {
		panic(err)
	}

	rlwePlainText := &lpr.Plaintext{Data: plainData}
	rlweCipherText, encryptionRandom, err := lpr.Encrypt(tumbler.RLWEPublic, rlwePlainText, Q, T, random)
	if err != nil {
		panic(err)
	}

	y := make([]vc.FastPoint, YNumber)
	for i := 0; i < int(YNumber); i++ {
		y[i], _ = protocol.CalculateY(rlwePlainText.Data[i*64 : i*64+64])
	}

	matrixA := &protocol.MatrixA{
		P0:    tumbler.RLWEPublic.PK0,
		P1:    tumbler.RLWEPublic.PK1,
		Delta: Q / T,
	}

	vectorT := &protocol.VectorT{
		T0: rlweCipherText.CT0,
		T1: rlweCipherText.CT1,
	}

	vectorS := &protocol.VectorS{
		U:  encryptionRandom.U,
		E1: encryptionRandom.E1,
		E2: encryptionRandom.E2,
		M:  rlwePlainText.Data,
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err = tumbler.GenProof(vectorT, matrixA, vectorS, random)
		if err != nil {
			panic(err)
		}
	}
	b.StopTimer()
}

func BenchmarkVerifyProof(b *testing.B) {
	secp256k1.InitNAFTables(9)
	protocol.SetCurve(secp256k1.FastCurve())
	protocol.SetCoreNum(16)

	random := rand.Reader
	D := protocol.D
	T := protocol.T
	Q := protocol.Q
	YNumber := protocol.YNumber
	tumbler, hSum1, hSum2 := initTumbler()
	plainData, err := lpr.GenerateRq(D, T/2, random)
	if err != nil {
		panic(err)
	}

	rlwePlainText := &lpr.Plaintext{Data: plainData}
	rlweCipherText, encryptionRandom, err := lpr.Encrypt(tumbler.RLWEPublic, rlwePlainText, Q, T, random)
	if err != nil {
		panic(err)
	}

	y := make([]vc.FastPoint, YNumber)
	for i := 0; i < int(YNumber); i++ {
		y[i], _ = protocol.CalculateY(rlwePlainText.Data[i*64 : i*64+64])
	}

	matrixA := &protocol.MatrixA{
		P0:    tumbler.RLWEPublic.PK0,
		P1:    tumbler.RLWEPublic.PK1,
		Delta: Q / T,
	}

	vectorT := &protocol.VectorT{
		T0: rlweCipherText.CT0,
		T1: rlweCipherText.CT1,
	}

	vectorS := &protocol.VectorS{
		U:  encryptionRandom.U,
		E1: encryptionRandom.E1,
		E2: encryptionRandom.E2,
		M:  rlwePlainText.Data,
	}
	proof, err := tumbler.GenProof(vectorT, matrixA, vectorS, random)
	if err != nil {
		panic(err)
	}

	bob := &protocol.Bob{
		G: tumbler.G,
		H: tumbler.H,
		U: tumbler.U,

		TumblerPublic: tumbler.Public,
		AlicePublic:   nil,
		HSum1:         hSum1,
		HSum2:         hSum2,
		Box:           tumbler.Box,
		B1List:        tumbler.B1List,

		Secret:     nil,
		Public:     nil,
		RLWEPublic: tumbler.RLWEPublic,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = bob.Verify(proof, rlweCipherText, bob.RLWEPublic, y)
		if err != nil {
			panic(err)
		}
	}
	b.StopTimer()
}
