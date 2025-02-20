package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"volley/adaptor"
	vc "volley/curve"
	"volley/lpr"
)

var Q int32 = 65536
var T int32 = 8
var D int32 = 1024
var YNumber int32 = 16
var coreNum int = 16
var L int32
var LP int32
var B int32 = 1
var BPrime int32 = 2
var B1 int32 = 11
var Step int32 = 16

func SetCoreNum(c int) {
	coreNum = c
}

func init() {
	L = 3*D*B + D*BPrime + 2*D*B1
	//L = 117694
	LP = L - 1
	LP |= LP >> 1
	LP |= LP >> 2
	LP |= LP >> 4
	LP |= LP >> 8
	LP |= LP >> 16
	LP++
}

type Tumbler struct {
	G []vc.FastPoint
	H []vc.FastPoint
	U vc.FastPoint

	Box    [][]*big.Int
	B1List []*big.Int

	Secret *big.Int
	Public vc.FastPoint

	BobPublic   vc.FastPoint
	AlicePublic vc.FastPoint

	RLWESecret *lpr.PrivateKey
	RLWEPublic *lpr.PublicKey
}

func (tumbler *Tumbler) Init(genPath, prePath, secretPath, alicePath, bobPath, rlwePrivate, rlwePublic string) error {
	ghuBytes, err := os.ReadFile(genPath)
	if err != nil {
		return err
	}
	if int32(len(ghuBytes)) < (L*2+1)*64 {
		return fmt.Errorf("Length error: %d, %d\n", len(ghuBytes), (L*2+1)*64)
	}
	tumbler.G = make([]vc.FastPoint, L)
	tumbler.H = make([]vc.FastPoint, L)
	for i := int32(0); i < L; i++ {
		tumbler.G[i] = fastCurve.NewPoint()
		gx := new(big.Int).SetBytes(ghuBytes[i*64 : i*64+32])
		gy := new(big.Int).SetBytes(ghuBytes[i*64+32 : i*64+64])
		tumbler.G[i].From(gx, gy)
	}
	hBytes := ghuBytes[64*L:]
	for i := int32(0); i < L; i++ {
		tumbler.H[i] = fastCurve.NewPoint()
		hx := new(big.Int).SetBytes(hBytes[i*64 : i*64+32])
		hy := new(big.Int).SetBytes(hBytes[i*64+32 : i*64+64])
		tumbler.H[i].From(hx, hy)
	}
	uBytes := ghuBytes[64*2*L:]
	tumbler.U = fastCurve.NewPoint()
	ux := new(big.Int).SetBytes(uBytes[0:32])
	uy := new(big.Int).SetBytes(uBytes[32:64])
	tumbler.U.From(ux, uy)

	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	tumbler.Secret = new(big.Int).SetBytes(secretBytes[0:32])
	publicX := new(big.Int).SetBytes(secretBytes[32:64])
	publicY := new(big.Int).SetBytes(secretBytes[64:96])
	tumbler.Public = fastCurve.NewPoint()
	tumbler.Public.From(publicX, publicY)

	bobBytes, err := os.ReadFile(bobPath)
	if err != nil {
		return err
	}
	publicX = new(big.Int).SetBytes(bobBytes[0:32])
	publicY = new(big.Int).SetBytes(bobBytes[32:64])
	tumbler.BobPublic = fastCurve.NewPoint()
	tumbler.BobPublic.From(publicX, publicY)

	aliceBytes, err := os.ReadFile(alicePath)
	if err != nil {
		return err
	}
	publicX = new(big.Int).SetBytes(aliceBytes[0:32])
	publicY = new(big.Int).SetBytes(aliceBytes[32:64])
	tumbler.AlicePublic = fastCurve.NewPoint()
	tumbler.AlicePublic.From(publicX, publicY)

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
	tumbler.Box = boxPrime

	b1List := make([]*big.Int, B1)
	for i := int32(0); i < B1; i++ {
		b1List[i] = big.NewInt(int64(1) << i)
	}
	b1List[B1-1].Sub(N, b1List[B1-1])
	tumbler.B1List = b1List

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
		tumbler.G[i].ImportTable(precomputes, true)
	}
	for i := int32(0); i < L; i++ {
		_, err = preFile.Read(precomputes)
		if err != nil {
			return err
		}
		tumbler.H[i].ImportTable(precomputes, true)
	}

	rlweSecretBytes, err := os.ReadFile(rlwePrivate)
	if err != nil {
		return err
	}
	tumbler.RLWESecret = &lpr.PrivateKey{
		Data: make([]int32, D),
	}
	for i := int32(0); i < D; i++ {
		if rlweSecretBytes[i] != 0 {
			tumbler.RLWESecret.Data[i] = -1
		}
	}

	rlwePublicBytes, err := os.ReadFile(rlwePublic)
	if err != nil {
		panic(err)
	}
	tumbler.RLWEPublic = new(lpr.PublicKey)
	err = tumbler.RLWEPublic.Deserialize(rlwePublicBytes, D, Q)
	if err != nil {
		panic(err)
	}

	return nil
}

func (tumbler *Tumbler) Step1x(random io.Reader) (*Proof, []vc.FastPoint, *lpr.Ciphertext, error) {

	plainData, err := lpr.GenerateRq(D, T/2, random)
	if err != nil {
		return nil, nil, nil, err
	}

	rlwePlainText := &lpr.Plaintext{Data: plainData}
	rlweCipherText, encryptionRandom, err := lpr.Encrypt(tumbler.RLWEPublic, rlwePlainText, Q, T, random)
	if err != nil {
		return nil, nil, nil, err
	}

	y := make([]vc.FastPoint, YNumber)
	for i := 0; i < int(YNumber); i++ {
		y[i], _ = CalculateY(rlwePlainText.Data[i*64 : i*64+64])
	}

	matrixA := &MatrixA{
		P0:    tumbler.RLWEPublic.PK0,
		P1:    tumbler.RLWEPublic.PK1,
		Delta: Q / T,
	}

	vectorT := &VectorT{
		T0: rlweCipherText.CT0,
		T1: rlweCipherText.CT1,
	}

	vectorS := &VectorS{
		U:  encryptionRandom.U,
		E1: encryptionRandom.E1,
		E2: encryptionRandom.E2,
		M:  rlwePlainText.Data,
	}

	proof, err := tumbler.GenProof(vectorT, matrixA, vectorS, random)
	if err != nil {
		return nil, nil, nil, err
	}
	return proof, y, rlweCipherText, nil
}

func (tumbler *Tumbler) Step1y(tx []byte, y []vc.FastPoint, random io.Reader) ([]*adaptor.Signature, error) {

	var err error
	sigs := make([]*adaptor.Signature, YNumber)
	for i := 0; i < int(YNumber); i++ {
		sigs[i], err = adaptor.SchnorrSignAdaptor(tx, y[i], tumbler.Secret, sha256.New(), random)
		if err != nil {
			return nil, err
		}
	}
	return sigs, nil
}

func RecoverFromYSecret(sum *big.Int) []int32 {
	N := fastCurve.Params().N
	halfN := new(big.Int).Sub(N, big.NewInt(1))
	halfN.Rsh(halfN, 1)
	current := new(big.Int).Set(sum)
	res := make([]int32, 64)
	sign := int64(1)
	if sum.Cmp(halfN) > 0 {
		current.Sub(current, N)
		current.Abs(current)
		sign = -1
	}
	carry := int64(0)
	dataF := big.NewInt(0xF)
	tail4 := new(big.Int)
	for i := 0; i < 64; i++ {
		tail4.And(current, dataF)
		value := tail4.Int64() + carry
		if value >= 8 {
			carry = 1
			value -= 16
		} else {
			carry = 0
		}
		res[i] = int32(value)
		current.Rsh(current, 4)
	}
	if sign == -1 {
		for i := 0; i < 64; i++ {
			res[i] = -res[i]
		}
	}

	return res
}

func CalculateY(msg []int32) (vc.FastPoint, *big.Int) {
	N := fastCurve.Params().N
	exp := big.NewInt(1)
	sum := big.NewInt(0)
	//d16 := big.NewInt(16)
	stepBig := big.NewInt(int64(Step))
	for i := 0; i < len(msg); i++ {
		tmp := new(big.Int).SetInt64(int64(msg[i]))
		tmp.Mul(tmp, exp)
		tmp.Mod(tmp, N)
		sum.Add(sum, tmp)
		sum.Mod(sum, N)
		exp.Mul(exp, stepBig)
		exp.Mod(exp, N)
	}
	if sum.Sign() == -1 {
		panic("Sign Error")
	}
	return fastCurve.FastBaseScalar(sum.Bytes()), sum
}

func (tumbler *Tumbler) GenProof(vectorT *VectorT, matrixA *MatrixA, vectorS *VectorS, random io.Reader) (*Proof, error) {
	var err error

	vectorAS := CalcRotAS(matrixA, vectorS)
	vectorR, err := PolyExactDiv(CalcTSubAs(vectorT, vectorAS), Q)
	if err != nil {
		return nil, err
	}

	bitStream := make([]byte, L)

	GetBitStream(bitStream, vectorS.U, int(B))
	offset := int(B) * len(vectorS.U)
	GetBitStream(bitStream[offset:], vectorS.E1, int(B))
	offset += int(B) * len(vectorS.E1)
	GetBitStream(bitStream[offset:], vectorS.E2, int(B))
	offset += int(B) * len(vectorS.E2)
	GetBitStream(bitStream[offset:], vectorS.M, int(BPrime))
	offset += int(BPrime) * len(vectorS.M)
	GetBitStream(bitStream[offset:], vectorR, int(B1))
	offset += int(B1) * len(vectorR)

	w1 := fastCurve.NewPoint()
	w2 := fastCurve.NewPoint()
	w3 := fastCurve.NewPoint()
	w3Start := int(3 * D * B)
	w3End := w3Start + int(D*BPrime)
	for i := 0; i < len(bitStream); i++ {
		if bitStream[i] != 0 {
			if i >= w3Start && i < w3End {
				fastCurve.FastPointAdd(w3, w3, tumbler.H[i])
			} else {
				fastCurve.FastPointAdd(w1, w1, tumbler.H[i])
			}
		} else {
			fastCurve.FastPointAdd(w2, w2, tumbler.G[i])
		}
	}

	N := fastCurve.Params().N
	o1, err := rand.Int(random, N)
	if err != nil {
		return nil, err
	}
	o2, err := rand.Int(random, N)
	if err != nil {
		return nil, err
	}
	o3, err := rand.Int(random, N)
	if err != nil {
		return nil, err
	}

	tmpEC := fastCurve.NewPoint()
	fastCurve.FastScalarMult(tmpEC, tumbler.U, o1.Bytes())
	fastCurve.FastPointAdd(w1, w1, tmpEC)
	fastCurve.FastScalarMult(tmpEC, tumbler.U, o2.Bytes())
	fastCurve.FastPointAdd(w2, w2, tmpEC)
	fastCurve.FastScalarMult(tmpEC, tumbler.U, o3.Bytes())
	fastCurve.FastPointAdd(w3, w3, tmpEC)

	rp := GetRandomParameter(w1, w2, w3)

	var vectorV []*big.Int
	if coreNum > 1 {
		vectorV = CalcLargeVectorVMultiCore(rp, matrixA, tumbler.B1List)
	} else {
		vectorV = CalcLargeVectorV(rp, matrixA, tumbler.B1List)
	}
	vectorZ := CalcLargeVectorZ(rp, tumbler.Box)

	//gPrime := make([]vc.FastPoint, L)
	//hPrime := make([]vc.FastPoint, L)
	gFactor := make([]*big.Int, LP)
	hFactor := make([]*big.Int, LP)

	fPrime := fastCurve.FastBaseScalar(rp.Theta.Bytes())
	//etaBytes := rp.Eta[0].Bytes()
	eta2Start := int(3 * D * B)
	eta2End := eta2Start + int(D*BPrime)

	lastPhiInv := fastCurve.Inverse(rp.Phi[L-1])
	var wg sync.WaitGroup

	for t := 0; t < coreNum; t++ {
		start := t * int(LP) / coreNum
		end := (t + 1) * int(LP) / coreNum
		wg.Add(1)
		go func(s, e, index int) {
			defer wg.Done()
			for i := s; i < e; i++ {
				if i >= int(L-1) {
					gFactor[i] = lastPhiInv
				} else {
					inv := fastCurve.Inverse(rp.Phi[i])
					gFactor[i] = inv
				}
				if i >= eta2Start && i < eta2End {
					hFactor[i] = rp.Eta[1]
				} else {
					hFactor[i] = rp.Eta[0]
				}
			}
		}(start, end, t)
	}
	wg.Wait()

	vectorV1, vectorV2 := CalcVectorV1V2(rp, vectorV, bitStream)

	o := new(big.Int).Mul(o1, rp.Eta[0])
	o.Mod(o, N)
	o.Add(o, new(big.Int).Mul(o3, rp.Eta[1]))
	o.Mod(o, N)
	o.Add(o, o2)
	o.Mod(o, N)
	x := big.NewInt(0)
	for i := int32(0); i < L; i++ {
		tmpVal := new(big.Int).Mul(vectorV1[i], vectorV2[i])
		tmpVal.Mod(tmpVal, N)
		x.Add(x, tmpVal)
		x.Mod(x, N)
	}
	data := make([]byte, 2*D*2)
	for i := int32(0); i < D; i++ {
		binary.LittleEndian.PutUint16(data[i*2:], uint16(vectorT.T0[i]))
	}
	for i := int32(0); i < D; i++ {
		binary.LittleEndian.PutUint16(data[2*D+i*2:], uint16(vectorT.T1[i]))
	}
	challengeBytes := sha256.Sum256(data)

	hashData := GetChallengeData(challengeBytes[:], []vc.FastPoint{w1, w2, w3}, nil)
	hashBig := new(big.Int).SetBytes(hashData)
	hashBig.Mod(hashBig, N)
	hashR := fastCurve.FastBaseScalar(hashBig.Bytes())

	sub1, challenge, err := tumbler.GenSubProof1(gFactor, hFactor, hashR, tumbler.U, vectorV1, vectorV2, x, o,
		hashData, random)
	if err != nil {
		panic(err)
	}
	sub2, err := tumbler.GenSubProof2(tumbler.H[3*D*B:3*D*B+D*BPrime], fPrime, tumbler.U, vectorZ,
		bitStream[3*D*B:3*D*B+D*BPrime], o3, challenge, random)
	if err != nil {
		panic(err)
	}
	return &Proof{
		Sub1: sub1,
		Sub2: sub2,
		W1:   w1,
		W2:   w2,
		W3:   w3,
	}, nil
}

func GetBitStream(stream []byte, source []int32, bitSize int) {
	pos := 0
	for _, i := range source {
		for j := 0; j < bitSize; j++ {
			stream[pos] = byte(uint32(i) & 0x1)
			i = i >> 1
			pos++
		}
	}
}

type RandomParameter struct {
	Alpha *big.Int
	Beta  []*big.Int
	Gamma []*big.Int
	Theta *big.Int
	Eta   []*big.Int
	Psi   *big.Int
	Phi   []*big.Int
}

func GetRandomParameter(w1, w2, w3 vc.FastPoint) *RandomParameter {
	N := fastCurve.Params().N
	challenge := GetChallengeData(nil, []vc.FastPoint{w1, w2, w3}, nil)
	data := make([]byte, len(challenge)+4)
	copy(data, challenge)
	slot := data[len(challenge):]

	count := uint32(0)
	rp := new(RandomParameter)
	binary.BigEndian.PutUint32(slot, count)
	count++
	digest := sha256.Sum256(data)
	rp.Alpha = new(big.Int).SetBytes(digest[:])
	rp.Alpha.Mod(rp.Alpha, N)
	rp.Beta = make([]*big.Int, 16)
	for i := range rp.Beta {
		binary.BigEndian.PutUint32(slot, count)
		count++
		digest = sha256.Sum256(data)
		rp.Beta[i] = new(big.Int).SetBytes(digest[:])
		rp.Beta[i].Mod(rp.Beta[i], N)
	}
	rp.Gamma = make([]*big.Int, 2*D)
	for i := range rp.Gamma {
		binary.BigEndian.PutUint32(slot, count)
		count++
		digest = sha256.Sum256(data)
		rp.Gamma[i] = new(big.Int).SetBytes(digest[:])
		rp.Gamma[i].Mod(rp.Gamma[i], N)
	}
	binary.BigEndian.PutUint32(slot, count)
	count++
	digest = sha256.Sum256(data)
	rp.Theta = new(big.Int).SetBytes(digest[:])
	rp.Theta.Mod(rp.Theta, N)

	rp.Eta = make([]*big.Int, 2)
	for i := range rp.Eta {
		binary.BigEndian.PutUint32(slot, count)
		count++
		digest = sha256.Sum256(data)
		rp.Eta[i] = new(big.Int).SetBytes(digest[:])
		rp.Eta[i].Mod(rp.Eta[i], N)
	}

	binary.BigEndian.PutUint32(slot, count)
	count++
	digest = sha256.Sum256(data)
	rp.Psi = new(big.Int).SetBytes(digest[:])
	rp.Psi.Mod(rp.Psi, N)

	rp.Phi = make([]*big.Int, L)
	for i := int32(0); i < L; i++ {
		binary.BigEndian.PutUint32(slot, count)
		count++
		digest = sha256.Sum256(data)
		rp.Phi[i] = new(big.Int).SetBytes(digest[:])
		rp.Phi[i].Mod(rp.Phi[i], N)
	}
	return rp
}

func CalcLargeVectorV(rp *RandomParameter, matrixA *MatrixA, b1List []*big.Int) []*big.Int {
	vectorV := make([]*big.Int, L)
	v := vectorV[:]
	N := fastCurve.Params().N

	for i := int32(0); i < D; i++ {
		sum := big.NewInt(0)
		for j := int32(0); j < i; j++ {
			value := int64(-matrixA.P0[j+D-i])
			tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j])
			tmpVal.Mod(tmpVal, N)
			sum.Add(sum, tmpVal)
			sum.Mod(sum, N)
		}
		for j := i; j < D; j++ {
			value := int64(matrixA.P0[j-i])
			tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j])
			tmpVal.Mod(tmpVal, N)
			sum.Add(sum, tmpVal)
			sum.Mod(sum, N)
		}
		for j := int32(0); j < i; j++ {
			value := int64(-matrixA.P1[j+D-i])
			tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j+D])
			tmpVal.Mod(tmpVal, N)
			sum.Add(sum, tmpVal)
			sum.Mod(sum, N)
		}
		for j := i; j < D; j++ {
			value := int64(matrixA.P1[j-i])
			tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j+D])
			tmpVal.Mod(tmpVal, N)
			sum.Add(sum, tmpVal)
			sum.Mod(sum, N)
		}
		v[i] = new(big.Int).Sub(N, sum)
	}
	for i := D; i < 3*D; i++ {
		v[i] = new(big.Int).Set(rp.Gamma[i-D])
		v[i].Sub(N, v[i])
	}
	v = vectorV[3*D:]

	minus2 := new(big.Int).Sub(N, big.NewInt(2))
	delta := big.NewInt(int64(matrixA.Delta))
	for i := int32(0); i < D; i++ {
		v[i*2] = new(big.Int).Mul(rp.Gamma[i], delta)
		v[i*2].Mod(v[i*2], N)
		tmp := new(big.Int).Mul(v[i*2], minus2)
		tmp.Mod(tmp, N)
		v[i*2+1] = tmp
	}
	v = v[2*D:]

	qBig := big.NewInt(int64(Q))
	for i := int32(0); i < 2*D; i++ {
		for j := int32(0); j < B1; j++ {
			tmpVal := new(big.Int).Mul(qBig, rp.Gamma[i])
			tmpVal.Mod(tmpVal, N)
			tmpVal.Mul(tmpVal, b1List[j])
			tmpVal.Mod(tmpVal, N)
			v[i*B1+j] = tmpVal
		}
	}
	return vectorV
}

func CalcLargeVectorZ(rp *RandomParameter, box [][]*big.Int) []*big.Int {
	z := make([]*big.Int, D*BPrime)
	for i := 0; i < len(z); i++ {
		z[i] = big.NewInt(0)
	}
	N := fastCurve.Params().N
	for i := int32(0); i < D*BPrime; i++ {
		for j := int32(0); j < 16; j++ {
			tmpVal := new(big.Int).Mul(box[j][i], rp.Beta[j])
			z[i].Add(z[i], tmpVal)
			z[i].Mod(z[i], N)
		}
	}

	return z
}

func CalcVectorV1V2(rp *RandomParameter, v []*big.Int, bitStream []byte) ([]*big.Int, []*big.Int) {
	v1 := make([]*big.Int, L)
	v2 := make([]*big.Int, L)
	N := fastCurve.Params().N
	for i := int32(0); i < L; i++ {
		v1[i] = new(big.Int).Set(v[i])
		if bitStream[i] == 1 {
		} else {
			v1[i].Add(v1[i], rp.Phi[i])
		}
		v1[i].Mod(v1[i], N)
		tmpVal := new(big.Int).Mul(rp.Phi[i], rp.Psi)
		v1[i].Add(v1[i], tmpVal)
		v1[i].Mod(v1[i], N)
	}
	psi1 := new(big.Int).Add(rp.Psi, big.NewInt(1))
	psi1.Mod(psi1, N)
	for i := int32(0); i < L; i++ {
		if bitStream[i] == 0 {
			v2[i] = new(big.Int).Set(rp.Psi)
		} else {
			v2[i] = new(big.Int).Set(psi1)
		}
	}
	return v1, v2
}

func CalcLargeVectorVMultiCore(rp *RandomParameter, matrixA *MatrixA, b1List []*big.Int) []*big.Int {
	vectorV := make([]*big.Int, L)

	N := fastCurve.Params().N
	minus2 := new(big.Int).Sub(N, big.NewInt(2))
	delta := big.NewInt(int64(matrixA.Delta))
	var wg sync.WaitGroup
	for t := 0; t < coreNum; t++ {
		v := vectorV[:]

		startIndex := t * int(D) / coreNum
		endIndex := (t + 1) * int(D) / coreNum
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			for i := int32(start); i < int32(end); i++ {
				sum := big.NewInt(0)
				for j := int32(0); j < i; j++ {
					value := int64(-matrixA.P0[j+D-i])
					tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j])
					tmpVal.Mod(tmpVal, N)
					sum.Add(sum, tmpVal)
					sum.Mod(sum, N)
				}
				for j := i; j < D; j++ {
					value := int64(matrixA.P0[j-i])
					tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j])
					tmpVal.Mod(tmpVal, N)
					sum.Add(sum, tmpVal)
					sum.Mod(sum, N)
				}
				for j := int32(0); j < i; j++ {
					value := int64(-matrixA.P1[j+D-i])
					tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j+D])
					tmpVal.Mod(tmpVal, N)
					sum.Add(sum, tmpVal)
					sum.Mod(sum, N)
				}
				for j := i; j < D; j++ {
					value := int64(matrixA.P1[j-i])
					tmpVal := new(big.Int).Mul(big.NewInt(value), rp.Gamma[j+D])
					tmpVal.Mod(tmpVal, N)
					sum.Add(sum, tmpVal)
					sum.Mod(sum, N)
				}
				v[i] = new(big.Int).Sub(N, sum)

			}

			for i := D + int32(start)*2; i < D+int32(end)*2; i++ {
				v[i] = new(big.Int).Set(rp.Gamma[i-D])
				v[i].Sub(N, v[i])
			}

			v = vectorV[3*D:]

			for i := start; i < end; i++ {
				v[i*2] = new(big.Int).Mul(rp.Gamma[i], delta)
				v[i*2].Mod(v[i*2], N)
				tmp := new(big.Int).Mul(v[i*2], minus2)
				tmp.Mod(tmp, N)
				v[i*2+1] = tmp
			}
			v = v[2*D:]

			qBig := big.NewInt(int64(Q))
			for i := int32(start) * 2; i < int32(end)*2; i++ {
				for j := int32(0); j < B1; j++ {
					tmpVal := new(big.Int).Mul(qBig, rp.Gamma[i])
					tmpVal.Mod(tmpVal, N)
					tmpVal.Mul(tmpVal, b1List[j])
					tmpVal.Mod(tmpVal, N)
					v[i*B1+j] = tmpVal
				}
			}

		}(startIndex, endIndex)
	}
	wg.Wait()

	return vectorV
}

func CalcRotAS(matrixA *MatrixA, vectorS *VectorS) []int32 {
	vectorAS := make([]int32, D*2)
	for i := int32(0); i < D; i++ {
		sum := int32(0)
		for j := int32(0); j <= i; j++ {
			v := matrixA.P0[i-j]
			sum += v * vectorS.U[j]
		}
		for j := i + 1; j < D; j++ {
			v := -matrixA.P0[i+D-j]
			sum += v * vectorS.U[j]
		}
		sum += vectorS.E1[i]
		sum += vectorS.M[i] * matrixA.Delta
		vectorAS[i] = sum
	}

	for i := int32(0); i < D; i++ {
		sum := int32(0)
		for j := int32(0); j <= i; j++ {
			v := matrixA.P1[i-j]
			sum += v * vectorS.U[j]
		}
		for j := i + 1; j < D; j++ {
			v := -matrixA.P1[i+D-j]
			sum += v * vectorS.U[j]
		}
		sum += vectorS.E2[i]
		vectorAS[i+D] = sum
	}
	return vectorAS
}

func CalcTSubAs(vectorT *VectorT, vectorAS []int32) []int32 {
	r := make([]int32, D*2)
	for i := int32(0); i < D; i++ {
		r[i] = vectorT.T0[i] - vectorAS[i]
	}
	for i := D; i < D*2; i++ {
		r[i] = vectorT.T1[i-D] - vectorAS[i]
	}
	return r
}

func (tumbler *Tumbler) Step4(tx []byte, sigA *adaptor.Signature, yPrime vc.FastPoint,
	lweCipherList []*lpr.LWECiphertext) (*adaptor.Signature, error) {
	verified := adaptor.SchnorrPreVerifyAdaptor(sigA, tx, yPrime, tumbler.AlicePublic, sha256.New())
	if !verified {
		return nil, fmt.Errorf("Failed to verify adaptor signature of alice\n")
	}
	plaintext := make([]int32, 64)
	for i := 0; i < len(plaintext); i++ {
		plaintext[i] = lpr.LWEDecrypt(lweCipherList[i], tumbler.RLWESecret, Q, T)
	}
	yRight, bn := CalculateY(plaintext)

	yRight.Neg()
	fastCurve.FastPointAdd(yRight, yRight, yPrime)
	if !yRight.IsZero() {
		return nil, fmt.Errorf("Y not verified")
	}

	sigPrime := new(adaptor.Signature)
	sigPrime.E = new(big.Int).Set(sigA.E)
	sigPrime.S = new(big.Int).Set(sigA.S)
	sigPrime.S.Add(sigPrime.S, bn)
	sigPrime.S.Mod(sigPrime.S, fastCurve.Params().N)

	return sigPrime, nil
}
