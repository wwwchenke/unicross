package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"sync"
	"volley/adaptor"
	vc "volley/curve"
	"volley/lpr"
)

type Bob struct {
	G []vc.FastPoint
	H []vc.FastPoint
	U vc.FastPoint

	TumblerPublic vc.FastPoint
	AlicePublic   vc.FastPoint
	HSum1         vc.FastPoint
	HSum2         vc.FastPoint
	Box           [][]*big.Int
	B1List        []*big.Int

	Secret     *big.Int
	Public     vc.FastPoint
	RLWEPublic *lpr.PublicKey

	rdmPlaintext *big.Int
	adaptorSig   *adaptor.Signature
}

func (bob *Bob) Init(genPath, prePath, tumblerPath, alicePath, secretPath, rlwePublic string) error {
	ghuBytes, err := os.ReadFile(genPath)
	if err != nil {
		return err
	}
	if int32(len(ghuBytes)) < (L*2+1)*64 {
		return fmt.Errorf("Length error: %d, %d\n", len(ghuBytes), (L*2+1)*64)
	}
	bob.G = make([]vc.FastPoint, L)
	bob.H = make([]vc.FastPoint, L)
	for i := int32(0); i < L; i++ {
		bob.G[i] = fastCurve.NewPoint()
		gx := new(big.Int).SetBytes(ghuBytes[i*64 : i*64+32])
		gy := new(big.Int).SetBytes(ghuBytes[i*64+32 : i*64+64])
		bob.G[i].From(gx, gy)
	}
	hBytes := ghuBytes[64*L:]
	for i := int32(0); i < L; i++ {
		bob.H[i] = fastCurve.NewPoint()
		hx := new(big.Int).SetBytes(hBytes[i*64 : i*64+32])
		hy := new(big.Int).SetBytes(hBytes[i*64+32 : i*64+64])
		bob.H[i].From(hx, hy)
	}
	uBytes := ghuBytes[64*2*L:]
	bob.U = fastCurve.NewPoint()
	ux := new(big.Int).SetBytes(uBytes[0:32])
	uy := new(big.Int).SetBytes(uBytes[32:64])
	bob.U.From(ux, uy)

	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	bob.Secret = new(big.Int).SetBytes(secretBytes[0:32])
	publicX := new(big.Int).SetBytes(secretBytes[32:64])
	publicY := new(big.Int).SetBytes(secretBytes[64:96])
	bob.Public = fastCurve.NewPoint()
	bob.Public.From(publicX, publicY)

	tumblerBytes, err := os.ReadFile(tumblerPath)
	if err != nil {
		return err
	}
	publicX = new(big.Int).SetBytes(tumblerBytes[0:32])
	publicY = new(big.Int).SetBytes(tumblerBytes[32:64])
	bob.TumblerPublic = fastCurve.NewPoint()
	bob.TumblerPublic.From(publicX, publicY)

	aliceBytes, err := os.ReadFile(alicePath)
	if err != nil {
		return err
	}
	publicX = new(big.Int).SetBytes(aliceBytes[0:32])
	publicY = new(big.Int).SetBytes(aliceBytes[32:64])
	bob.AlicePublic = fastCurve.NewPoint()
	bob.AlicePublic.From(publicX, publicY)

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
		tmpForBox[i] = new(big.Int).Mul(tmpForBox[i-1], big.NewInt(int64(Step)))
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
	bob.Box = boxPrime

	b1List := make([]*big.Int, B1)
	for i := int32(0); i < B1; i++ {
		b1List[i] = big.NewInt(int64(1) << i)
	}
	b1List[B1-1].Sub(N, b1List[B1-1])
	bob.B1List = b1List

	preFile, err := os.Open(prePath)
	if err != nil {
		return err
	}
	defer func() { _ = preFile.Close() }()

	precomputes := make([]byte, 8*64)
	for i := int32(0); i < L; i++ {
		_, err = preFile.Read(precomputes)
		if err != nil {
			return err
		}
		bob.G[i].ImportTable(precomputes, true)
	}
	for i := int32(0); i < L; i++ {
		_, err = preFile.Read(precomputes)
		if err != nil {
			return err
		}
		bob.H[i].ImportTable(precomputes, true)
	}
	pointBytes := make([]byte, 64)
	_, err = preFile.Read(pointBytes)
	if err != nil {
		return err
	}
	hx := new(big.Int).SetBytes(pointBytes[0:32])
	hy := new(big.Int).SetBytes(pointBytes[32:64])
	bob.HSum1 = fastCurve.NewPoint()
	bob.HSum1.From(hx, hy)

	_, err = preFile.Read(pointBytes)
	if err != nil {
		return err
	}
	hx = new(big.Int).SetBytes(pointBytes[0:32])
	hy = new(big.Int).SetBytes(pointBytes[32:64])
	bob.HSum2 = fastCurve.NewPoint()
	bob.HSum2.From(hx, hy)

	rlwePublicBytes, err := os.ReadFile(rlwePublic)
	if err != nil {
		panic(err)
	}
	bob.RLWEPublic = new(lpr.PublicKey)
	err = bob.RLWEPublic.Deserialize(rlwePublicBytes, D, Q)
	if err != nil {
		panic(err)
	}

	return nil
}

func (bob *Bob) Step2(tx []byte, proof *Proof, rlweCipher *lpr.Ciphertext, y []vc.FastPoint,
	sig *adaptor.Signature, index int, random io.Reader) (*lpr.Ciphertext, vc.FastPoint, error) {

	err := bob.Verify(proof, rlweCipher, bob.RLWEPublic, y)
	if err != nil {
		return nil, nil, err
	}

	verified := adaptor.SchnorrPreVerifyAdaptor(sig, tx, y[index], bob.TumblerPublic, sha256.New())
	if !verified {
		return nil, nil, fmt.Errorf("Adaptor signature not verified\n")
	}

	rdmPlainData, err := lpr.GenerateRq(D, T/2, random)
	if err != nil {
		return nil, nil, err
	}

	rlweRdmPlaintext := &lpr.Plaintext{Data: rdmPlainData}
	rlweRdmCiphertext, _, err := lpr.Encrypt(bob.RLWEPublic, rlweRdmPlaintext, Q, T, random)
	if err != nil {
		return nil, nil, err
	}

	rlweNewCiphertext := lpr.CipherAdd(rlweRdmCiphertext, rlweCipher, Q)

	yPrime, ySecret := CalculateY(rlweRdmPlaintext.Data[index*64 : index*64+64])
	fastCurve.FastPointAdd(yPrime, yPrime, y[index])

	bob.rdmPlaintext = ySecret
	bob.adaptorSig = sig

	return rlweNewCiphertext, yPrime, nil
}

func (bob *Bob) Verify(proof *Proof, rlweCipher *lpr.Ciphertext, puzzleKey *lpr.PublicKey,
	yPoints []vc.FastPoint) error {
	N := fastCurve.Params().N
	rp := GetRandomParameter(proof.W1, proof.W2, proof.W3)

	matrixA := &MatrixA{
		P0:    puzzleKey.PK0,
		P1:    puzzleKey.PK1,
		Delta: Q / T,
	}

	vectorT := new(VectorT)
	vectorT.T0 = rlweCipher.CT0
	vectorT.T1 = rlweCipher.CT1

	var vectorV []*big.Int
	if coreNum > 1 {
		vectorV = CalcLargeVectorVMultiCore(rp, matrixA, bob.B1List)
	} else {
		vectorV = CalcLargeVectorV(rp, matrixA, bob.B1List)
	}
	vectorZ := CalcLargeVectorZ(rp, bob.Box)

	fPrime := fastCurve.FastBaseScalar(rp.Theta.Bytes())

	ipssPieces := make([]vc.FastPoint, coreNum)
	gScalar := make([][]byte, L)
	gFactor := make([]vc.FastBn, LP)

	var wg sync.WaitGroup
	for t := 0; t < coreNum; t++ {
		start := t * int(L) / coreNum
		end := (t + 1) * int(L) / coreNum
		wg.Add(1)
		go func(s, e, index int) {
			defer wg.Done()
			for i := s; i < e; i++ {
				inv := fastCurve.Inverse(rp.Phi[i])
				gFactor[i] = fastCurve.NewBn()
				gFactor[i].From(inv)

				tmp := new(big.Int).Mul(rp.Phi[i], rp.Psi)
				tmp.Mod(tmp, N)
				tmp.Add(tmp, vectorV[i])
				tmp.Mod(tmp, N)
				tmp.Mul(tmp, inv)
				tmp.Mod(tmp, N)
				gScalar[i] = tmp.Bytes()
			}

			ipssPieces[index] = fastCurve.NewPoint()
			fastCurve.FasterPolynomial(ipssPieces[index], bob.G[s:e], gScalar[s:e], true)

		}(start, end, t)
	}
	wg.Wait()

	Cipss := fastCurve.NewPoint()
	fastCurve.FastScalarMult(Cipss, proof.W1, rp.Eta[0].Bytes())
	fastCurve.FastPointAdd(Cipss, Cipss, proof.W2)
	tmpPoint := fastCurve.NewPoint()
	fastCurve.FastScalarMult(tmpPoint, proof.W3, rp.Eta[1].Bytes())
	fastCurve.FastPointAdd(Cipss, Cipss, tmpPoint)

	for i := 0; i < coreNum; i++ {
		fastCurve.FastPointAdd(Cipss, Cipss, ipssPieces[i])
	}

	eta1Psi := new(big.Int).Mul(rp.Eta[0], rp.Psi)
	eta1Psi.Mod(eta1Psi, N)
	eta2Psi := new(big.Int).Mul(rp.Eta[1], rp.Psi)
	eta2Psi.Mod(eta2Psi, N)

	fastCurve.FastScalarMult(tmpPoint, bob.HSum1, eta1Psi.Bytes())
	fastCurve.FastPointAdd(Cipss, Cipss, tmpPoint)
	fastCurve.FastScalarMult(tmpPoint, bob.HSum2, eta2Psi.Bytes())
	fastCurve.FastPointAdd(Cipss, Cipss, tmpPoint)

	Cipsp := fastCurve.NewPoint()
	scalarList := make([][]byte, 16)
	for i := 0; i < 16; i++ {
		tmpVal := new(big.Int).Mul(rp.Theta, rp.Beta[i])
		tmpVal.Mod(tmpVal, N)
		scalarList[i] = tmpVal.Bytes()
	}
	fastCurve.FastPolynomial(Cipsp, yPoints, scalarList)
	fastCurve.FastPointAdd(Cipsp, Cipsp, proof.W3)
	//Cipsp.CopyFrom(proof.W3)
	//for i := int32(0); i < YNumber; i++ {
	//	tmpVal := new(big.Int).Mul(rp.Theta, rp.Beta[i])
	//	tmpVal.Mod(tmpVal, N)
	//	fastCurve.FastScalarMult(tmpPoint, yPoints[i], tmpVal.Bytes())
	//	fastCurve.FastPointAdd(Cipsp, Cipsp, tmpPoint)
	//}

	x := big.NewInt(0)
	for i := int32(0); i < D; i++ {
		tmpVal := new(big.Int).Mul(big.NewInt(int64(vectorT.T0[i])), rp.Gamma[i])
		x.Add(x, tmpVal)
		x.Mod(x, N)
		tmpVal.Mul(big.NewInt(int64(vectorT.T1[i])), rp.Gamma[i+D])
		x.Add(x, tmpVal)
		x.Mod(x, N)
	}

	sumV := new(big.Int).Add(vectorV[0], vectorV[1])
	for i := int32(2); i < L; i++ {
		sumV.Add(sumV, vectorV[i])
		sumV.Mod(sumV, N)
	}
	x.Add(x, new(big.Int).Mul(sumV, rp.Psi))
	x.Mod(x, N)

	psiSum := new(big.Int).Add(rp.Psi, new(big.Int).Mul(rp.Psi, rp.Psi))
	psiSum.Mod(psiSum, N)

	sumPhi := new(big.Int).Add(rp.Phi[0], rp.Phi[1])
	for i := int32(2); i < L; i++ {
		sumPhi.Add(sumPhi, rp.Phi[i])
		sumPhi.Mod(sumPhi, N)
	}
	x.Add(x, new(big.Int).Mul(sumPhi, psiSum))
	x.Mod(x, N)

	data := make([]byte, 2*D*2)
	for i := int32(0); i < D; i++ {
		binary.LittleEndian.PutUint16(data[i*2:], uint16(vectorT.T0[i]))
	}
	for i := int32(0); i < D; i++ {
		binary.LittleEndian.PutUint16(data[2*D+i*2:], uint16(vectorT.T1[i]))
	}
	challengeBytes := sha256.Sum256(data)
	hashData := GetChallengeData(challengeBytes[:], []vc.FastPoint{proof.W1, proof.W2, proof.W3}, nil)
	hashBig := new(big.Int).SetBytes(hashData)
	hashBig.Mod(hashBig, N)
	hashR := fastCurve.FastBaseScalar(hashBig.Bytes())

	CipssPrime := fastCurve.NewPoint()
	fastCurve.FastScalarMult(CipssPrime, hashR, x.Bytes())
	fastCurve.FastPointAdd(CipssPrime, CipssPrime, Cipss)

	verified, challenge := bob.VerifySub1(hashR, CipssPrime, proof, hashData, gFactor, rp.Eta)
	if !verified {
		fmt.Println("Failed to verify sub proof 1")
		//return fmt.Errorf("Failed to verify sub proof 1\n")
	}

	verified = bob.VerifySub2(fPrime, Cipsp, vectorZ, challenge, proof)
	if !verified {
		return fmt.Errorf("Failed to verify sub proof 2\n")
	}

	return nil
}

func (bob *Bob) VerifySub1(hashR, CipssPrime vc.FastPoint, proof *Proof, challengeBytes []byte,
	gFactor []vc.FastBn, eta []*big.Int) (bool, []byte) {
	N := fastCurve.Params().N
	length := int(LP)
	gSlot := make([]vc.FastPoint, length)
	hSlot := make([]vc.FastPoint, length)
	hFactor := make([]vc.FastBn, length)
	gScalar := make([][]byte, length)
	hScalar := make([][]byte, length)

	eta2Start := D * 3 * B
	eta2End := eta2Start + D*BPrime

	for i := int32(0); i < L; i++ {
		gSlot[i] = bob.G[i]
		hSlot[i] = bob.H[i]
		//gFactor[i] = fastCurve.NewBn()
		hFactor[i] = fastCurve.NewBn()
		//gFactor[i].From(phi[i])
		if i >= eta2Start && i < eta2End {
			hFactor[i].From(eta[1])
		} else {
			hFactor[i].From(eta[0])
		}
	}
	for i := L; i < int32(length); i++ {
		gSlot[i] = bob.G[L-1]
		hSlot[i] = bob.H[L-1]
		gFactor[i] = fastCurve.NewBn()
		gFactor[i].CopyFrom(gFactor[L-1])
		hFactor[i] = fastCurve.NewBn()
		if i >= eta2Start && i < eta2End {
			hFactor[i].From(eta[1])
		} else {
			hFactor[i].From(eta[0])
		}
	}
	var hashC, hashCInv *big.Int
	cList := make([][]byte, len(proof.Sub1.TL))
	cInvList := make([][]byte, len(proof.Sub1.TR))
	stackDepth := 0

	sub := proof.Sub1
	for length > 1 {
		half := length / 2
		length = half

		challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{sub.TL[stackDepth], sub.TR[stackDepth]},
			nil)
		hashC = new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
		hashCInv = fastCurve.Inverse(hashC)
		hashCBytes := hashC.Bytes()
		invBytes := hashCInv.Bytes()
		cList[stackDepth] = hashCBytes
		cInvList[stackDepth] = invBytes
		bnC := fastCurve.NewBn()
		bnC.From(hashC)
		bnCInv := fastCurve.NewBn()
		bnCInv.From(hashCInv)

		if length >= 16 && coreNum > 1 {
			var wg sync.WaitGroup
			for t := 0; t < coreNum; t++ {
				wg.Add(1)
				go func(index, seg int) {
					defer wg.Done()
					start := index * int(LP) / coreNum
					end := (index + 1) * int(LP) / coreNum
					for i := start; i < end; i++ {
						if (i/seg)%2 == 1 {
							fastCurve.FastOrderMul(gFactor[i], gFactor[i], bnC)
							fastCurve.FastOrderMul(hFactor[i], hFactor[i], bnCInv)
						}
					}
				}(t, half)
			}
			wg.Wait()
		} else {
			for i := 0; i < int(LP); i++ {
				if (i/half)%2 == 1 {
					fastCurve.FastOrderMul(gFactor[i], gFactor[i], bnC)
					fastCurve.FastOrderMul(hFactor[i], hFactor[i], bnCInv)
				}
			}
		}

		stackDepth++
	}
	tmpPoint := fastCurve.NewPoint()
	fastCurve.FastPolynomial(tmpPoint, proof.Sub1.TL, cInvList)
	fastCurve.FastPointAdd(CipssPrime, CipssPrime, tmpPoint)
	fastCurve.FastPolynomial(tmpPoint, proof.Sub1.TR, cList)
	fastCurve.FastPointAdd(CipssPrime, CipssPrime, tmpPoint)

	gPieces := make([]vc.FastPoint, coreNum)
	hPieces := make([]vc.FastPoint, coreNum)
	var wg sync.WaitGroup
	for t := 0; t < coreNum; t++ {
		startIndex := t * int(LP) / coreNum
		endIndex := (t + 1) * int(LP) / coreNum
		wg.Add(1)
		go func(start, end, index int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				hScalar[i] = hFactor[i].Back()
				gScalar[i] = gFactor[i].Back()
			}
			gPieces[index] = fastCurve.NewPoint()
			hPieces[index] = fastCurve.NewPoint()
			fastCurve.FasterPolynomial(gPieces[index], gSlot[start:end], gScalar[start:end], true)
			fastCurve.FasterPolynomial(hPieces[index], hSlot[start:end], hScalar[start:end], true)
		}(startIndex, endIndex, t)
	}
	wg.Wait()

	for i := 1; i < coreNum; i++ {
		fastCurve.FastPointAdd(hPieces[0], hPieces[0], hPieces[i])
		fastCurve.FastPointAdd(gPieces[0], gPieces[0], gPieces[i])
	}

	challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{sub.BigC, sub.BigCPrime}, nil)
	randomXi := new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
	randomXiInv := fastCurve.Inverse(randomXi)

	ecLeft := fastCurve.NewPoint()
	ecList := []vc.FastPoint{CipssPrime, proof.Sub1.BigCPrime}
	fastCurve.FastPolynomial(ecLeft, ecList, [][]byte{randomXi.Bytes(), randomXiInv.Bytes()})
	fastCurve.FastPointAdd(ecLeft, ecLeft, proof.Sub1.BigC)

	tmpVal := new(big.Int).Mul(randomXiInv, proof.Sub1.E1)
	tmpVal.Mod(tmpVal, N)
	tmpVal.Mul(tmpVal, proof.Sub1.E2)
	tmpVal.Mod(tmpVal, N)

	ecRight := fastCurve.NewPoint()
	ecList = []vc.FastPoint{gPieces[0], hPieces[0], hashR, bob.U}
	scalarList := [][]byte{proof.Sub1.E1.Bytes(), proof.Sub1.E2.Bytes(), tmpVal.Bytes(), proof.Sub1.O.Bytes()}
	fastCurve.FastPolynomial(ecRight, ecList, scalarList)
	ecRight.Neg()
	zeroPoint := fastCurve.NewPoint()
	fastCurve.FastPointAdd(zeroPoint, ecLeft, ecRight)
	return zeroPoint.IsZero(), challengeBytes
}

func (bob *Bob) VerifySub2(f, Cipsp vc.FastPoint, vectorZ []*big.Int, challengeBytes []byte, proof *Proof) bool {
	h := bob.H[3*D*B : 3*D*B+D*BPrime]
	N := fastCurve.Params().N
	count := int32(math.Log2(float64(D * BPrime)))
	length := 1 << count

	zSlot := make([]*big.Int, length)
	hSlot := make([]vc.FastPoint, length)
	hFactor := make([]vc.FastBn, length)
	hScalar := make([][]byte, length)

	for i := int32(0); i < D*BPrime; i++ {
		zSlot[i] = new(big.Int).Set(vectorZ[i])
		hFactor[i] = fastCurve.NewBn()
		hSlot[i] = h[i]
	}
	for i := D * BPrime; i < int32(length); i++ {
		zSlot[i] = new(big.Int).Set(vectorZ[L-1])
		hFactor[i] = fastCurve.NewBn()
		hSlot[i] = h[L-1]
	}

	var hashC, hashCInv *big.Int
	cList := make([][]byte, count)
	cInvList := make([][]byte, count)
	stackDepth := 0
	sub := proof.Sub2
	for length > 1 {
		half := length / 2
		length = half
		//fastCurve.FastPointAdd(accL, accL, proof.Sub2.TL[stackDepth])
		//fastCurve.FastPointAdd(accR, accR, proof.Sub2.TR[stackDepth])
		//hashC = GetHashByEC(accL, accR)
		challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{sub.TL[stackDepth], sub.TR[stackDepth]}, nil)
		hashC = new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
		hashCInv = fastCurve.Inverse(hashC)
		cList[stackDepth] = hashC.Bytes()
		cInvList[stackDepth] = hashCInv.Bytes()

		bnC := fastCurve.NewBn()
		bnC.From(hashC)
		bnCInv := fastCurve.NewBn()
		bnCInv.From(hashCInv)
		if coreNum > 1 {
			var wg sync.WaitGroup
			for t := 0; t < coreNum; t++ {

				wg.Add(1)
				go func(index, seg int) {
					defer wg.Done()
					start := index * seg / coreNum
					end := (index + 1) * seg / coreNum

					for i := start; i < end; i++ {
						tmpVal := new(big.Int).Mul(zSlot[seg+i], hashC)
						tmpVal.Mod(tmpVal, N)
						zSlot[i].Add(zSlot[i], tmpVal)
						zSlot[i].Mod(zSlot[i], N)
					}
					start = index * len(hFactor) / coreNum
					end = (index + 1) * len(hFactor) / coreNum
					if stackDepth > 0 {
						for i := start; i < end; i++ {
							if (i/seg)%2 == 0 {
							} else {
								fastCurve.FastOrderMul(hFactor[i], hFactor[i], bnC)
							}
						}
					} else {
						for i := start; i < end; i++ {
							if (i/seg)%2 == 0 {
							} else {
								hFactor[i].CopyFrom(bnC)
							}
						}
					}

				}(t, half)
			}
			wg.Wait()
		} else {
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(zSlot[half+i], hashC)
				tmpVal.Mod(tmpVal, N)
				zSlot[i].Add(zSlot[i], tmpVal)
				zSlot[i].Mod(zSlot[i], N)
			}
			if stackDepth > 0 {
				for i := 0; i < len(hFactor); i++ {
					if (i/half)%2 == 0 {
					} else {
						fastCurve.FastOrderMul(hFactor[i], hFactor[i], bnC)
					}
				}
			} else {
				for i := 0; i < len(hFactor); i++ {
					if (i/half)%2 == 0 {
					} else {
						hFactor[i].CopyFrom(bnC)
					}
				}
			}
		}
		//tmpPoint := fastCurve.NewPoint()
		//ecList := []vc.FastPoint{proof.Sub2.TL[stackDepth], proof.Sub2.TR[stackDepth]}
		//fastCurve.FastPolynomial(tmpPoint, ecList, [][]byte{hashC.Bytes(), hashCInv.Bytes()})
		//fastCurve.FastPointAdd(Cipsp, Cipsp, tmpPoint)
		stackDepth++
	}
	tmpPoint := fastCurve.NewPoint()
	fastCurve.FastPolynomial(tmpPoint, sub.TL, cList)
	fastCurve.FastPointAdd(Cipsp, Cipsp, tmpPoint)
	fastCurve.FastPolynomial(tmpPoint, sub.TR, cInvList)
	fastCurve.FastPointAdd(Cipsp, Cipsp, tmpPoint)

	hPieces := make([]vc.FastPoint, coreNum)
	var wg sync.WaitGroup
	for t := 0; t < coreNum; t++ {
		startIndex := t * len(hFactor) / coreNum
		endIndex := (t + 1) * len(hFactor) / coreNum
		wg.Add(1)
		go func(start, end, index int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				hScalar[i] = hFactor[i].Back()
			}
			hPieces[index] = fastCurve.NewPoint()
			fastCurve.FasterPolynomial(hPieces[index], hSlot[start:end], hScalar[start:end], true)
		}(startIndex, endIndex, t)
	}
	wg.Wait()

	for i := 1; i < coreNum; i++ {
		fastCurve.FastPointAdd(hPieces[0], hPieces[0], hPieces[i])
	}

	challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{proof.Sub2.BigC}, nil)
	randomXi := new(big.Int).SetBytes(challengeBytes)
	randomXi.Mod(randomXi, N)

	ecRight := fastCurve.NewPoint()
	tmpVal := new(big.Int).Mul(zSlot[0], proof.Sub2.E1)
	tmpVal.Mod(tmpVal, N)
	ecList := []vc.FastPoint{Cipsp, hPieces[0], f, bob.U}
	scalarList := [][]byte{randomXi.Bytes(), proof.Sub2.E1.Bytes(), tmpVal.Bytes(), proof.Sub2.E2.Bytes()}
	fastCurve.FastPolynomial(ecRight, ecList, scalarList)
	ecRight.Neg()
	fastCurve.FastPointAdd(ecRight, ecRight, proof.Sub2.BigC)

	return ecRight.IsZero()
}

func (bob *Bob) Step6(plainNum *big.Int) *adaptor.Signature {
	tmp := new(big.Int).Sub(plainNum, bob.rdmPlaintext)
	res := new(adaptor.Signature)
	res.E = new(big.Int).Set(bob.adaptorSig.E)
	res.S = new(big.Int).Add(bob.adaptorSig.S, tmp)
	res.S.Mod(res.S, fastCurve.Params().N)

	return res
}

func (bob *Bob) SaveState(rdmPlainPath string) error {
	data := make([]byte, 32)
	bob.rdmPlaintext.FillBytes(data)
	err := os.WriteFile(rdmPlainPath, data, os.ModePerm)
	return err
}

func (bob *Bob) LoadStateIfNeeded(ySecretPath, sigListPath string, index int) error {
	if bob.rdmPlaintext != nil {
		return nil
	}
	ySecretBytes, err := os.ReadFile(ySecretPath)
	if err != nil {
		return err
	}
	bob.rdmPlaintext = new(big.Int).SetBytes(ySecretBytes)
	sigListBytes, err := os.ReadFile(sigListPath)
	if err != nil {
		return err
	}
	sigList, err := DeserializeSigList(sigListBytes)
	if err != nil {
		return err
	}
	bob.adaptorSig = sigList[index]
	return nil
}
