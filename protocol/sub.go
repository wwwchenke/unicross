package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"sync"
	vc "volley/curve"
)

type SubProof1 struct {
	TL        []vc.FastPoint
	TR        []vc.FastPoint
	BigC      vc.FastPoint
	BigCPrime vc.FastPoint
	E1        *big.Int
	E2        *big.Int
	O         *big.Int
}

type SubProof2 struct {
	TL   []vc.FastPoint
	TR   []vc.FastPoint
	BigC vc.FastPoint
	E1   *big.Int
	E2   *big.Int
}

func (sp1 *SubProof1) Serialize() []byte {
	count := len(sp1.TL)
	data := make([]byte, 64*count+64*count+64+64+32*3+4)
	binary.BigEndian.PutUint32(data, uint32(count))
	offset := 4
	for _, tl := range sp1.TL {
		x, y := tl.Back()
		x.FillBytes(data[offset : offset+32])
		y.FillBytes(data[offset : offset+64])
		offset += 64
	}
	for _, tr := range sp1.TR {
		x, y := tr.Back()
		x.FillBytes(data[offset : offset+32])
		y.FillBytes(data[offset : offset+64])
		offset += 64
	}
	x, y := sp1.BigC.Back()
	x.FillBytes(data[offset : offset+32])
	y.FillBytes(data[offset : offset+64])
	offset += 64
	x, y = sp1.BigCPrime.Back()
	x.FillBytes(data[offset : offset+32])
	y.FillBytes(data[offset : offset+64])
	offset += 64
	sp1.E1.FillBytes(data[offset : offset+32])
	offset += 32
	sp1.E2.FillBytes(data[offset : offset+32])
	offset += 32
	sp1.O.FillBytes(data[offset : offset+32])
	return data
}

func (sp1 *SubProof2) Serialize() []byte {
	count := len(sp1.TL)
	data := make([]byte, 64*count+64*count+64+32*2+4)
	binary.BigEndian.PutUint32(data, uint32(count))
	offset := 4
	for _, tl := range sp1.TL {
		x, y := tl.Back()
		x.FillBytes(data[offset : offset+32])
		y.FillBytes(data[offset : offset+64])
		offset += 64
	}
	for _, tr := range sp1.TR {
		x, y := tr.Back()
		x.FillBytes(data[offset : offset+32])
		y.FillBytes(data[offset : offset+64])
		offset += 64
	}
	x, y := sp1.BigC.Back()
	x.FillBytes(data[offset : offset+32])
	y.FillBytes(data[offset : offset+64])
	offset += 64
	sp1.E1.FillBytes(data[offset : offset+32])
	offset += 32
	sp1.E2.FillBytes(data[offset : offset+32])
	return data
}

func (sp1 *SubProof1) SerializeCompressed() []byte {
	count := len(sp1.TL)
	data := make([]byte, 33*count+33*count+33+33+32*3+2)
	data[0] = 2
	data[1] = byte(count)
	offset := 2
	for _, tl := range sp1.TL {
		x, y := tl.Back()
		data[offset] = 0x02 | byte(y.Bit(0))
		x.FillBytes(data[offset+1 : offset+33])
		offset += 33
	}
	for _, tr := range sp1.TR {
		x, y := tr.Back()
		data[offset] = 0x02 | byte(y.Bit(0))
		x.FillBytes(data[offset+1 : offset+33])
		offset += 33
	}
	x, y := sp1.BigC.Back()
	data[offset] = 0x02 | byte(y.Bit(0))
	x.FillBytes(data[offset+1 : offset+33])
	offset += 33
	x, y = sp1.BigCPrime.Back()
	data[offset] = 0x02 | byte(y.Bit(0))
	x.FillBytes(data[offset+1 : offset+33])
	offset += 33
	sp1.E1.FillBytes(data[offset : offset+32])
	offset += 32
	sp1.E2.FillBytes(data[offset : offset+32])
	offset += 32
	sp1.O.FillBytes(data[offset : offset+32])
	return data
}

func (sp1 *SubProof2) SerializeCompressed() []byte {
	count := len(sp1.TL)
	data := make([]byte, 33*count+33*count+33+32*2+2)
	data[0] = 2
	data[1] = byte(count)
	offset := 2
	for _, tl := range sp1.TL {
		x, y := tl.Back()
		data[offset] = 0x02 | byte(y.Bit(0))
		x.FillBytes(data[offset+1 : offset+33])
		offset += 33
	}
	for _, tr := range sp1.TR {
		x, y := tr.Back()
		data[offset] = 0x02 | byte(y.Bit(0))
		x.FillBytes(data[offset+1 : offset+33])
		offset += 33
	}
	x, y := sp1.BigC.Back()
	data[offset] = 0x02 | byte(y.Bit(0))
	x.FillBytes(data[offset+1 : offset+33])
	offset += 33
	sp1.E1.FillBytes(data[offset : offset+32])
	offset += 32
	sp1.E2.FillBytes(data[offset : offset+32])
	return data
}

func GetChallengeData(base []byte, ec []vc.FastPoint, bn []*big.Int) []byte {
	h := sha256.New()
	h.Reset()
	if len(base) > 0 {
		h.Write(base)
	}
	if len(ec) > 0 {
		for _, e := range ec {
			ex, ey := e.Back()
			h.Write(ex.Bytes())
			h.Write(ey.Bytes())
		}
	}
	if len(bn) > 0 {
		for _, b := range bn {
			h.Write(b.Bytes())
		}
	}
	return h.Sum(nil)
}

func (tumbler *Tumbler) GenSubProof1(gFactor, hFactor []*big.Int, hashR, u vc.FastPoint, v1, v2 []*big.Int, x,
	o *big.Int, challengeBytes []byte, random io.Reader) (*SubProof1, []byte, error) {
	N := fastCurve.Params().N
	//hashR := GetHashByECBN(g, hSum, Cipss, u, x)
	length := int(LP)
	count := int32(math.Log2(float64(LP)))

	gSlot := make([]vc.FastPoint, length)
	hSlot := make([]vc.FastPoint, length)
	v1Slot := make([]*big.Int, length)
	v2Slot := make([]*big.Int, length)
	for i := int32(0); i < L; i++ {
		gSlot[i] = fastCurve.NewPoint()
		hSlot[i] = fastCurve.NewPoint()
		gSlot[i].CopyFrom(tumbler.G[i])
		hSlot[i].CopyFrom(tumbler.H[i])
		v1Slot[i] = new(big.Int).Set(v1[i])
		v2Slot[i] = new(big.Int).Set(v2[i])
	}
	for i := int(L); i < length; i++ {
		gSlot[i] = fastCurve.NewPoint()
		hSlot[i] = fastCurve.NewPoint()
		gSlot[i].CopyFrom(tumbler.G[L-1])
		hSlot[i].CopyFrom(tumbler.H[L-1])
		v1Slot[i] = big.NewInt(0)
		v2Slot[i] = big.NewInt(0)
	}
	var sigmaL, sigmaR, exp, hashC, hashCInv *big.Int
	tL := make([]vc.FastPoint, count)
	tR := make([]vc.FastPoint, count)
	//accL := fastCurve.NewPoint()
	//accR := fastCurve.NewPoint()
	for i := int32(0); i < count; i++ {
		tL[i] = fastCurve.NewPoint()
		tR[i] = fastCurve.NewPoint()
	}

	stackDepth := 0

	fullScalarG := make([][]byte, length)
	fullScalarH := make([][]byte, length)
	var wg sync.WaitGroup
	for length > 1 {
		half := length / 2
		length = half
		var err error
		sigmaL, err = rand.Int(random, N)
		if err != nil {
			return nil, nil, err
		}
		sigmaR, err = rand.Int(random, N)
		if err != nil {
			return nil, nil, err
		}

		if length >= 16 && coreNum > 1 {

			threadNum := half / 8
			if threadNum >= coreNum {
				threadNum = coreNum
			}
			scalarG := fullScalarG[:half]
			scalarH := fullScalarH[:half]

			tLPieces := make([]vc.FastPoint, threadNum)
			tRPieces := make([]vc.FastPoint, threadNum)
			for i := 0; i < threadNum; i++ {
				tLPieces[i] = fastCurve.NewPoint()
				tRPieces[i] = fastCurve.NewPoint()
			}
			for t := 0; t < threadNum; t++ {
				startIndex := t * half / threadNum
				endIndex := (t + 1) * half / threadNum
				wg.Add(1)
				go func(start, end, index int, tl, tr []vc.FastPoint) {
					defer wg.Done()
					for i := start; i < end; i++ {
						if stackDepth > 0 {
							scalarG[i] = v1Slot[half+i].Bytes()
							scalarH[i] = v2Slot[i].Bytes()
						} else {
							tmpVal := new(big.Int).Mul(gFactor[i], v1Slot[half+i])
							tmpVal.Mod(tmpVal, N)
							scalarG[i] = tmpVal.Bytes()
							tmpVal = new(big.Int).Mul(hFactor[half+i], v2Slot[i])
							tmpVal.Mod(tmpVal, N)
							scalarH[i] = tmpVal.Bytes()
						}
					}
					tmpG := fastCurve.NewPoint()
					tmpH := fastCurve.NewPoint()
					if stackDepth > 0 {
						fastCurve.FastPolynomial(tmpG, gSlot[start:end], scalarG[start:end])
						fastCurve.FastPolynomial(tmpH, hSlot[half+start:half+end], scalarH[start:end])
					} else {
						fastCurve.FasterPolynomial(tmpG, gSlot[start:end], scalarG[start:end], true)
						fastCurve.FasterPolynomial(tmpH, hSlot[half+start:half+end], scalarH[start:end], true)
					}
					fastCurve.FastPointAdd(tmpG, tmpG, tmpH)
					fastCurve.FastPointAdd(tl[index], tl[index], tmpG)

					for i := start; i < end; i++ {
						if stackDepth > 0 {
							scalarG[i] = v1Slot[i].Bytes()
							scalarH[i] = v2Slot[half+i].Bytes()
						} else {
							tmpVal := new(big.Int).Mul(gFactor[half+i], v1Slot[i])
							tmpVal.Mod(tmpVal, N)
							scalarG[i] = tmpVal.Bytes()
							tmpVal = new(big.Int).Mul(hFactor[i], v2Slot[half+i])
							tmpVal.Mod(tmpVal, N)
							scalarH[i] = tmpVal.Bytes()
						}
					}
					if stackDepth > 0 {
						fastCurve.FastPolynomial(tmpG, gSlot[half+start:half+end], scalarG[start:end])
						fastCurve.FastPolynomial(tmpH, hSlot[start:end], scalarH[start:end])
					} else {
						fastCurve.FasterPolynomial(tmpG, gSlot[half+start:half+end], scalarG[start:end], true)
						fastCurve.FasterPolynomial(tmpH, hSlot[start:end], scalarH[start:end], true)
					}
					fastCurve.FastPointAdd(tmpG, tmpG, tmpH)
					fastCurve.FastPointAdd(tr[index], tr[index], tmpG)

				}(startIndex, endIndex, t, tLPieces, tRPieces)
			}
			wg.Wait()
			for i := 0; i < threadNum; i++ {
				fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tLPieces[i])
				fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tRPieces[i])
			}
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(v1Slot[half+i], v2Slot[i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			tmpG := fastCurve.NewPoint()
			fastCurve.FastScalarMult(tmpG, hashR, exp.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpG)
			fastCurve.FastScalarMult(tmpG, u, sigmaL.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpG)
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(v1Slot[i], v2Slot[half+i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			fastCurve.FastScalarMult(tmpG, hashR, exp.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpG)
			fastCurve.FastScalarMult(tmpG, u, sigmaR.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpG)

			challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{tL[stackDepth], tR[stackDepth]}, nil)
			hashC = new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
			hashCInv = fastCurve.Inverse(hashC)

			val := new(big.Int).Mul(hashCInv, sigmaL)
			o.Add(o, val)
			val = new(big.Int).Mul(hashC, sigmaR)
			o.Add(o, val)
			o.Mod(o, N)

			hashCBytes := hashC.Bytes()
			invBytes := hashCInv.Bytes()
			for t := 0; t < threadNum; t++ {
				startIndex := t * half / threadNum
				endIndex := (t + 1) * half / threadNum
				wg.Add(1)
				go func(start, end int) {
					defer wg.Done()
					for i := start; i < end; i++ {
						tmpVal := new(big.Int).Mul(hashCInv, v1Slot[half+i])
						tmpVal.Mod(tmpVal, N)
						v1Slot[i].Add(v1Slot[i], tmpVal)
						v1Slot[i].Mod(v1Slot[i], N)
					}
					for i := start; i < end; i++ {
						tmpVal := new(big.Int).Mul(hashC, v2Slot[half+i])
						tmpVal.Mod(tmpVal, N)
						v2Slot[i].Add(v2Slot[i], tmpVal)
						v2Slot[i].Mod(v2Slot[i], N)
					}
					for i := start; i < end; i++ {
						if stackDepth > 0 {
							fastCurve.FastScalarMult(gSlot[half+i], gSlot[half+i], hashCBytes)
							fastCurve.FastPointAdd(gSlot[i], gSlot[i], gSlot[half+i])
						} else {
							tmpVal := new(big.Int).Mul(hashC, gFactor[half+i])
							tmpVal.Mod(tmpVal, N)
							fastCurve.FasterPolynomial(gSlot[i], []vc.FastPoint{gSlot[i], gSlot[half+i]},
								[][]byte{gFactor[i].Bytes(), tmpVal.Bytes()}, true)
						}

					}
					for i := start; i < end; i++ {
						if stackDepth > 0 {
							fastCurve.FastScalarMult(hSlot[half+i], hSlot[half+i], invBytes)
							fastCurve.FastPointAdd(hSlot[i], hSlot[i], hSlot[half+i])
						} else {
							tmpVal := new(big.Int).Mul(hashCInv, hFactor[half+i])
							tmpVal.Mod(tmpVal, N)
							fastCurve.FasterPolynomial(hSlot[i], []vc.FastPoint{hSlot[i], hSlot[half+i]},
								[][]byte{hFactor[i].Bytes(), tmpVal.Bytes()}, true)
						}
					}
				}(startIndex, endIndex)
			}
			wg.Wait()

			stackDepth++
		} else {
			scalarG := fullScalarG[:half]
			scalarH := fullScalarH[:half]
			if stackDepth > 0 {
				for i := 0; i < half; i++ {
					scalarG[i] = v1Slot[half+i].Bytes()
					scalarH[i] = v2Slot[i].Bytes()
				}
			} else {
				for i := 0; i < half; i++ {
					tmpVal := new(big.Int).Mul(v1Slot[half+i], gFactor[i])
					tmpVal.Mod(tmpVal, N)
					scalarG[i] = tmpVal.Bytes()
					tmpVal = new(big.Int).Mul(v2Slot[i], hFactor[half+i])
					tmpVal.Mod(tmpVal, N)
					scalarH[i] = tmpVal.Bytes()
				}
			}
			tmpG := fastCurve.NewPoint()
			tmpH := fastCurve.NewPoint()
			if stackDepth > 0 {
				fastCurve.FastPolynomial(tmpG, gSlot[0:half], scalarG)
				fastCurve.FastPolynomial(tmpH, hSlot[half:2*half], scalarH)
			} else {
				fastCurve.FasterPolynomial(tmpG, gSlot[0:half], scalarG, true)
				fastCurve.FasterPolynomial(tmpH, hSlot[half:2*half], scalarH, true)
			}
			fastCurve.FastPointAdd(tmpG, tmpG, tmpH)
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpG)
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(v1Slot[half+i], v2Slot[i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			fastCurve.FastScalarMult(tmpG, hashR, exp.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpG)
			fastCurve.FastScalarMult(tmpH, u, sigmaL.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpH)
			if stackDepth > 0 {
				for i := 0; i < half; i++ {
					scalarG[i] = v1Slot[i].Bytes()
					scalarH[i] = v2Slot[half+i].Bytes()
				}
			} else {
				for i := 0; i < half; i++ {
					tmpVal := new(big.Int).Mul(v1Slot[i], gFactor[half+i])
					tmpVal.Mod(tmpVal, N)
					scalarG[i] = tmpVal.Bytes()
					tmpVal.Mul(v2Slot[half+i], hFactor[i])
					tmpVal.Mod(tmpVal, N)
					scalarH[i] = tmpVal.Bytes()
				}
			}
			if stackDepth > 0 {
				fastCurve.FastPolynomial(tmpG, gSlot[half:2*half], scalarG)
				fastCurve.FastPolynomial(tmpH, hSlot[0:half], scalarH)
			} else {
				fastCurve.FasterPolynomial(tmpG, gSlot[half:2*half], scalarG, true)
				fastCurve.FasterPolynomial(tmpH, hSlot[0:half], scalarH, true)
			}
			fastCurve.FastPointAdd(tmpG, tmpG, tmpH)
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpG)
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(v1Slot[i], v2Slot[half+i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			fastCurve.FastScalarMult(tmpG, hashR, exp.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpG)
			fastCurve.FastScalarMult(tmpH, u, sigmaR.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpH)

			//fastCurve.FastPointAdd(accL, accL, tL[stackDepth])
			//fastCurve.FastPointAdd(accR, accR, tR[stackDepth])
			//hashC = GetHashByEC(accL, accR)
			challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{tL[stackDepth], tR[stackDepth]}, nil)
			hashC = new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
			hashCInv = fastCurve.Inverse(hashC)

			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(hashCInv, v1Slot[half+i])
				tmpVal.Mod(tmpVal, N)
				v1Slot[i].Add(v1Slot[i], tmpVal)
				v1Slot[i].Mod(v1Slot[i], N)
			}
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(hashC, v2Slot[half+i])
				tmpVal.Mod(tmpVal, N)
				v2Slot[i].Add(v2Slot[i], tmpVal)
				v2Slot[i].Mod(v2Slot[i], N)
			}
			val := new(big.Int).Mul(hashCInv, sigmaL)
			o.Add(o, val)
			val = new(big.Int).Mul(hashC, sigmaR)
			o.Add(o, val)
			o.Mod(o, N)
			hashCBytes := hashC.Bytes()
			invBytes := hashCInv.Bytes()
			for i := 0; i < half; i++ {
				if stackDepth > 0 {
					fastCurve.FastScalarMult(gSlot[half+i], gSlot[half+i], hashCBytes)
				} else {
					tmpVal := new(big.Int).Mul(hashC, gFactor[half+i])
					tmpVal.Mod(tmpVal, N)
					fastCurve.FastScalarMult(gSlot[i], gSlot[i], gFactor[i].Bytes())
					fastCurve.FastScalarMult(gSlot[half+i], gSlot[half+i], tmpVal.Bytes())

				}
				fastCurve.FastPointAdd(gSlot[i], gSlot[i], gSlot[half+i])
			}
			for i := 0; i < half; i++ {
				if stackDepth > 0 {
					fastCurve.FastScalarMult(hSlot[half+i], hSlot[half+i], invBytes)
				} else {
					tmpVal := new(big.Int).Mul(hashCInv, hFactor[half+i])
					tmpVal.Mod(tmpVal, N)
					fastCurve.FastScalarMult(hSlot[i], hSlot[i], hFactor[i].Bytes())
					fastCurve.FastScalarMult(hSlot[half+i], hSlot[half+i], tmpVal.Bytes())
				}
				fastCurve.FastPointAdd(hSlot[i], hSlot[i], hSlot[half+i])
			}
			stackDepth++
		}
	}
	randomY1, err := rand.Int(random, N)
	if err != nil {
		return nil, nil, err
	}
	randomY2, err := rand.Int(random, N)
	if err != nil {
		return nil, nil, err
	}
	randomSigma, err := rand.Int(random, N)
	if err != nil {
		return nil, nil, err
	}
	randomSigmaPrime, err := rand.Int(random, N)
	if err != nil {
		return nil, nil, err
	}

	bigC := fastCurve.NewPoint()
	fastCurve.FastScalarMult(bigC, gSlot[0], randomY1.Bytes())
	tmpVal := fastCurve.NewPoint()
	fastCurve.FastScalarMult(tmpVal, hSlot[0], randomY2.Bytes())
	fastCurve.FastPointAdd(bigC, bigC, tmpVal)
	tmpBn := new(big.Int).Mul(v2Slot[0], randomY1)
	tmpBn.Mod(tmpBn, N)
	tmpBn.Add(tmpBn, new(big.Int).Mul(v1Slot[0], randomY2))
	tmpBn.Mod(tmpBn, N)
	fastCurve.FastScalarMult(tmpVal, hashR, tmpBn.Bytes())
	fastCurve.FastPointAdd(bigC, bigC, tmpVal)
	fastCurve.FastScalarMult(tmpVal, u, randomSigma.Bytes())
	fastCurve.FastPointAdd(bigC, bigC, tmpVal)

	tmpBn.Mul(randomY1, randomY2)
	tmpBn.Mod(tmpBn, N)
	bigCPrime := fastCurve.NewPoint()
	fastCurve.FastScalarMult(bigCPrime, hashR, tmpBn.Bytes())
	fastCurve.FastScalarMult(tmpVal, u, randomSigmaPrime.Bytes())
	fastCurve.FastPointAdd(bigCPrime, bigCPrime, tmpVal)

	challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{bigC, bigCPrime}, nil)
	randomXi := new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
	randomXiInv := fastCurve.Inverse(randomXi)

	e1 := new(big.Int).Mul(randomXi, v1Slot[0])
	e1.Add(e1, randomY1)
	e1.Mod(e1, N)

	e2 := new(big.Int).Mul(randomXi, v2Slot[0])
	e2.Add(e2, randomY2)
	e2.Mod(e2, N)

	o.Mul(o, randomXi)
	o.Add(o, randomSigma)
	o.Mod(o, N)
	o.Add(o, new(big.Int).Mul(randomXiInv, randomSigmaPrime))
	o.Mod(o, N)

	//fmt.Println("Final result")
	//fmt.Println(randomXi.Text(16))
	//fmt.Println(randomXiInv.Text(16))
	//fmt.Println(e1.Text(16))
	//fmt.Println(e2.Text(16))
	//fmt.Println(o.Text(16))

	return &SubProof1{
		TL:        tL,
		TR:        tR,
		BigC:      bigC,
		BigCPrime: bigCPrime,
		E1:        e1,
		E2:        e2,
		O:         new(big.Int).Set(o),
	}, challengeBytes, nil
}

func (tumbler *Tumbler) GenSubProof2(h []vc.FastPoint, f, u vc.FastPoint, z []*big.Int, streamA []byte,
	o3 *big.Int, challengeBytes []byte, random io.Reader) (*SubProof2, error) {
	N := fastCurve.Params().N
	count := int32(math.Log2(float64(D * BPrime)))
	length := 1 << count

	hSlot := make([]vc.FastPoint, length)
	zSlot := make([]*big.Int, length)
	aSlot := make([]*big.Int, length)
	for i := int32(0); i < D*BPrime; i++ {
		hSlot[i] = fastCurve.NewPoint()
		hSlot[i].CopyFrom(h[i])
		zSlot[i] = new(big.Int).Set(z[i])
		aSlot[i] = big.NewInt(int64(streamA[i]))
	}
	for i := D * BPrime; i < int32(length); i++ {
		hSlot[i] = fastCurve.NewPoint()
		hSlot[i].CopyFrom(h[D*BPrime-1])
		zSlot[i] = new(big.Int).Set(z[D*BPrime-1])
		aSlot[i] = big.NewInt(int64(streamA[D*BPrime-1]))
	}

	var sigmaL, sigmaR, exp *big.Int
	tL := make([]vc.FastPoint, count)
	tR := make([]vc.FastPoint, count)
	//accL := fastCurve.NewPoint()
	//accR := fastCurve.NewPoint()
	for i := int32(0); i < count; i++ {
		tL[i] = fastCurve.NewPoint()
		tR[i] = fastCurve.NewPoint()
	}
	fullScalarH := make([][]byte, length)
	var wg sync.WaitGroup
	stackDepth := 0
	for length > 1 {
		var err error
		sigmaL, err = rand.Int(random, N)
		if err != nil {
			return nil, err
		}
		sigmaR, err = rand.Int(random, N)
		if err != nil {
			return nil, err
		}

		if length >= 16 && coreNum > 1 {
			half := length / 2
			length = half
			scalarH := fullScalarH[:half]

			threadNum := half / 8
			if threadNum >= coreNum {
				threadNum = coreNum
			}
			tLPieces := make([]vc.FastPoint, threadNum)
			tRPieces := make([]vc.FastPoint, threadNum)
			for i := 0; i < threadNum; i++ {
				tLPieces[i] = fastCurve.NewPoint()
				tRPieces[i] = fastCurve.NewPoint()
			}

			for t := 0; t < threadNum; t++ {
				startIndex := t * half / threadNum
				endIndex := (t + 1) * half / threadNum
				wg.Add(1)
				go func(start, end, index int) {
					defer wg.Done()
					tmpH := fastCurve.NewPoint()
					if stackDepth == 0 {
						for i := start; i < end; i++ {
							if streamA[i] == 1 {
								fastCurve.FastPointAdd(tLPieces[index], tLPieces[index], hSlot[half+i])
							}

							hi := half + i
							if hi >= int(L) {
								hi = int(L) - 1
							}
							if streamA[hi] == 1 {
								fastCurve.FastPointAdd(tRPieces[index], tRPieces[index], hSlot[i])
							}
						}
					} else {
						for i := start; i < end; i++ {
							scalarH[i] = aSlot[i].Bytes()
						}
						fastCurve.FastPolynomial(tmpH, hSlot[half+start:half+end], scalarH[start:end])
						fastCurve.FastPointAdd(tLPieces[index], tLPieces[index], tmpH)

						for i := start; i < end; i++ {
							scalarH[i] = aSlot[half+i].Bytes()
						}
						fastCurve.FastPolynomial(tmpH, hSlot[start:end], scalarH[start:end])
						fastCurve.FastPointAdd(tRPieces[index], tRPieces[index], tmpH)
					}
				}(startIndex, endIndex, t)
			}
			wg.Wait()
			for i := 0; i < threadNum; i++ {
				fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tLPieces[i])
				fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tRPieces[i])
			}
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(aSlot[i], zSlot[half+i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			tmpH := fastCurve.NewPoint()
			fastCurve.FastScalarMult(tmpH, f, exp.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpH)
			fastCurve.FastScalarMult(tmpH, u, sigmaL.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpH)
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(aSlot[half+i], zSlot[i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			fastCurve.FastScalarMult(tmpH, f, exp.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpH)
			fastCurve.FastScalarMult(tmpH, u, sigmaR.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpH)

			challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{tL[stackDepth], tR[stackDepth]}, nil)
			hashC := new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
			hashCInv := fastCurve.Inverse(hashC)
			hashCBytes := hashC.Bytes()

			val := new(big.Int).Mul(hashC, sigmaL)
			o3.Add(o3, val)
			val = new(big.Int).Mul(hashCInv, sigmaR)
			o3.Add(o3, val)
			o3.Mod(o3, N)

			for t := 0; t < threadNum; t++ {
				startIndex := t * half / threadNum
				endIndex := (t + 1) * half / threadNum
				wg.Add(1)
				go func(start, end int) {
					defer wg.Done()

					tmpPoint := fastCurve.NewPoint()
					for i := start; i < end; i++ {
						fastCurve.FastScalarMult(tmpPoint, hSlot[i+half], hashCBytes)
						fastCurve.FastPointAdd(hSlot[i], hSlot[i], tmpPoint)
					}
					for i := start; i < end; i++ {
						tmpVal := new(big.Int).Mul(zSlot[half+i], hashC)
						tmpVal.Mod(tmpVal, N)
						zSlot[i].Add(zSlot[i], tmpVal)
						zSlot[i].Mod(zSlot[i], N)
					}

					for i := start; i < end; i++ {
						tmpVal := new(big.Int).Mul(aSlot[half+i], hashCInv)
						tmpVal.Mod(tmpVal, N)
						aSlot[i].Add(aSlot[i], tmpVal)
						aSlot[i].Mod(aSlot[i], N)
					}

				}(startIndex, endIndex)
			}
			wg.Wait()

			stackDepth++
		} else {
			half := length / 2
			length = half
			scalarH := fullScalarH[:half]
			tmpH := fastCurve.NewPoint()
			if stackDepth == 0 {
				for i := 0; i < half; i++ {
					if streamA[i] == 1 {
						fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], hSlot[half+i])
					}
				}
			} else {
				for i := 0; i < half; i++ {
					scalarH[i] = aSlot[i].Bytes()
				}
				fastCurve.FastPolynomial(tmpH, hSlot[half:2*half], scalarH)
				fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpH)
			}

			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(aSlot[i], zSlot[half+i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			fastCurve.FastScalarMult(tmpH, f, exp.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpH)
			fastCurve.FastScalarMult(tmpH, u, sigmaL.Bytes())
			fastCurve.FastPointAdd(tL[stackDepth], tL[stackDepth], tmpH)
			if stackDepth == 0 {
				for i := 0; i < half; i++ {
					index := half + i
					if index >= int(L) {
						index = int(L) - 1
					}
					if streamA[index] == 1 {
						fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], hSlot[i])
					}
				}
			} else {
				for i := 0; i < half; i++ {
					scalarH[i] = aSlot[half+i].Bytes()
				}
				fastCurve.FastPolynomial(tmpH, hSlot[0:half], scalarH)
				fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpH)
			}
			exp = big.NewInt(0)
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(aSlot[half+i], zSlot[i])
				exp.Add(exp, tmpVal)
				exp.Mod(exp, N)
			}
			fastCurve.FastScalarMult(tmpH, f, exp.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpH)
			fastCurve.FastScalarMult(tmpH, u, sigmaR.Bytes())
			fastCurve.FastPointAdd(tR[stackDepth], tR[stackDepth], tmpH)

			challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{tL[stackDepth], tR[stackDepth]}, nil)
			hashC := new(big.Int).Mod(new(big.Int).SetBytes(challengeBytes), N)
			hashCInv := fastCurve.Inverse(hashC)
			hashCBytes := hashC.Bytes()

			tmpPoint := fastCurve.NewPoint()
			for i := 0; i < half; i++ {
				fastCurve.FastScalarMult(tmpPoint, hSlot[i+half], hashCBytes)
				fastCurve.FastPointAdd(hSlot[i], hSlot[i], tmpPoint)
			}
			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(zSlot[half+i], hashC)
				tmpVal.Mod(tmpVal, N)
				zSlot[i].Add(zSlot[i], tmpVal)
				zSlot[i].Mod(zSlot[i], N)
			}

			for i := 0; i < half; i++ {
				tmpVal := new(big.Int).Mul(aSlot[half+i], hashCInv)
				tmpVal.Mod(tmpVal, N)
				aSlot[i].Add(aSlot[i], tmpVal)
				aSlot[i].Mod(aSlot[i], N)
			}
			val := new(big.Int).Mul(hashC, sigmaL)
			o3.Add(o3, val)
			val = new(big.Int).Mul(hashCInv, sigmaR)
			o3.Add(o3, val)
			o3.Mod(o3, N)

			stackDepth++
		}
	}
	randomY1, err := rand.Int(random, N)
	if err != nil {
		return nil, err
	}
	randomY2, err := rand.Int(random, N)
	if err != nil {
		return nil, err
	}

	bigC := fastCurve.NewPoint()
	tmpVal := new(big.Int).Mul(randomY1, zSlot[0])
	tmpVal.Mod(tmpVal, N)
	fastCurve.FastPolynomial(bigC, []vc.FastPoint{hSlot[0], f, u},
		[][]byte{randomY1.Bytes(), tmpVal.Bytes(), randomY2.Bytes()})

	challengeBytes = GetChallengeData(challengeBytes, []vc.FastPoint{bigC}, nil)
	randomXi := new(big.Int).SetBytes(challengeBytes)
	randomXi.Mod(randomXi, N)

	e1 := new(big.Int).Sub(randomY1, new(big.Int).Mul(randomXi, aSlot[0]))
	e1.Mod(e1, N)

	e2 := new(big.Int).Sub(randomY2, new(big.Int).Mul(randomXi, o3))
	e2.Mod(e2, N)

	return &SubProof2{
		TL:   tL,
		TR:   tR,
		BigC: bigC,
		E1:   e1,
		E2:   e2,
	}, nil
}
