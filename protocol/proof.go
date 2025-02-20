package protocol

import (
	"fmt"
	"math"
	"math/big"
	"volley/adaptor"
	vc "volley/curve"
)

type Proof struct {
	W1   vc.FastPoint
	W2   vc.FastPoint
	W3   vc.FastPoint
	Sub1 *SubProof1
	Sub2 *SubProof2
}

func storePoint(data []byte, point vc.FastPoint) {
	x, y := point.Back()
	x.FillBytes(data[0:32])
	y.FillBytes(data[32:64])
}

func storePointCompressed(data []byte, point vc.FastPoint) {
	data[0] = 0x02
	x, y := point.Back()
	x.FillBytes(data[1:33])
	data[0] |= byte(y.Bit(0))
}

func getPoint(data []byte) vc.FastPoint {
	x := new(big.Int).SetBytes(data[0:32])
	y := new(big.Int).SetBytes(data[32:64])
	point := fastCurve.NewPoint()
	point.From(x, y)
	return point
}

func GetPointCompressed(data []byte) vc.FastPoint {
	return getPointCompressed(data)
}

func getPointCompressed(data []byte) vc.FastPoint {
	P := fastCurve.Params().P
	x := new(big.Int).SetBytes(data[1:33])
	sign := uint(data[0] & 0x1)
	t := new(big.Int).Mul(x, x)
	t.Mod(t, P)
	t.Mul(t, x)
	t.Mod(t, P)
	t.Add(t, fastCurve.Params().B)
	t.Mod(t, P)
	y := new(big.Int).ModSqrt(t, P)
	if y.Bit(0)^sign == 1 {
		y.Sub(P, y)
	}
	point := fastCurve.NewPoint()
	point.From(x, y)
	return point
}

func (p *Proof) Deserialize(data []byte) (err error) {
	defer func() {
		fatal := recover()
		if fatal != nil {
			err = fmt.Errorf("Deserialization error\n")
		}
	}()

	offset := 0
	p.W1 = getPoint(data[offset:])
	offset += 64
	p.W2 = getPoint(data[offset:])
	offset += 64
	p.W3 = getPoint(data[offset:])
	offset += 64
	p.Sub1 = new(SubProof1)
	length1 := int(math.Log2(float64(LP)))
	p.Sub1.TL = make([]vc.FastPoint, length1)
	p.Sub1.TR = make([]vc.FastPoint, length1)
	for i := 0; i < length1; i++ {
		p.Sub1.TL[i] = getPoint(data[offset:])
		offset += 64
	}
	for i := 0; i < length1; i++ {
		p.Sub1.TR[i] = getPoint(data[offset:])
		offset += 64
	}
	p.Sub1.BigC = getPoint(data[offset:])
	offset += 64
	p.Sub1.BigCPrime = getPoint(data[offset:])
	offset += 64
	p.Sub1.E1 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.E2 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.O = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub2 = new(SubProof2)
	length2 := int(math.Log2(float64(D * BPrime)))
	p.Sub2.TL = make([]vc.FastPoint, length2)
	p.Sub2.TR = make([]vc.FastPoint, length2)
	for i := 0; i < length2; i++ {
		p.Sub2.TL[i] = getPoint(data[offset:])
		offset += 64
	}
	for i := 0; i < length2; i++ {
		p.Sub2.TR[i] = getPoint(data[offset:])
		offset += 64
	}
	p.Sub2.BigC = getPoint(data[offset:])
	offset += 64
	p.Sub2.E1 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub2.E2 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	if offset != len(data) {
		panic("size error")
	}

	err = nil
	return
}

func (p *Proof) Serialize() []byte {
	size := (3+3+2*int(len(p.Sub1.TL))+2*int(len(p.Sub2.TL)))*64 + 5*32
	data := make([]byte, size)
	offset := 0
	storePoint(data[offset:], p.W1)
	offset += 64
	storePoint(data[offset:], p.W2)
	offset += 64
	storePoint(data[offset:], p.W3)
	offset += 64
	for _, point := range p.Sub1.TL {
		storePoint(data[offset:], point)
		offset += 64
	}
	for _, point := range p.Sub1.TR {
		storePoint(data[offset:], point)
		offset += 64
	}
	storePoint(data[offset:], p.Sub1.BigC)
	offset += 64
	storePoint(data[offset:], p.Sub1.BigCPrime)
	offset += 64

	p.Sub1.E1.FillBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.E2.FillBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.O.FillBytes(data[offset : offset+32])
	offset += 32

	for _, point := range p.Sub2.TL {
		storePoint(data[offset:], point)
		offset += 64
	}
	for _, point := range p.Sub2.TR {
		storePoint(data[offset:], point)
		offset += 64
	}
	storePoint(data[offset:], p.Sub2.BigC)
	offset += 64
	p.Sub2.E1.FillBytes(data[offset : offset+32])
	offset += 32
	p.Sub2.E2.FillBytes(data[offset : offset+32])
	offset += 32
	if offset != size {
		panic("Size error")
	}

	return data
}

func (p *Proof) SerializeCompressed() []byte {
	size := (3+3+2*int(len(p.Sub1.TL))+2*int(len(p.Sub2.TL)))*33 + 5*32
	data := make([]byte, size)
	offset := 0
	storePointCompressed(data[offset:], p.W1)
	offset += 33
	storePointCompressed(data[offset:], p.W2)
	offset += 33
	storePointCompressed(data[offset:], p.W3)
	offset += 33
	for _, point := range p.Sub1.TL {
		storePointCompressed(data[offset:], point)
		offset += 33
	}
	for _, point := range p.Sub1.TR {
		storePointCompressed(data[offset:], point)
		offset += 33
	}
	storePointCompressed(data[offset:], p.Sub1.BigC)
	offset += 33
	storePointCompressed(data[offset:], p.Sub1.BigCPrime)
	offset += 33

	p.Sub1.E1.FillBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.E2.FillBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.O.FillBytes(data[offset : offset+32])
	offset += 32

	for _, point := range p.Sub2.TL {
		storePointCompressed(data[offset:], point)
		offset += 33
	}
	for _, point := range p.Sub2.TR {
		storePointCompressed(data[offset:], point)
		offset += 33
	}
	storePointCompressed(data[offset:], p.Sub2.BigC)
	offset += 33
	p.Sub2.E1.FillBytes(data[offset : offset+32])
	offset += 32
	p.Sub2.E2.FillBytes(data[offset : offset+32])
	offset += 32
	if offset != size {
		panic("Size error")
	}

	return data
}

func (p *Proof) DeserializeCompressed(data []byte) (err error) {
	defer func() {
		fatal := recover()
		if fatal != nil {
			err = fmt.Errorf("Deserialization error\n")
		}
	}()

	offset := 0
	p.W1 = getPointCompressed(data[offset:])
	offset += 33
	p.W2 = getPointCompressed(data[offset:])
	offset += 33
	p.W3 = getPointCompressed(data[offset:])
	offset += 33
	p.Sub1 = new(SubProof1)
	length1 := int(math.Log2(float64(LP)))
	p.Sub1.TL = make([]vc.FastPoint, length1)
	p.Sub1.TR = make([]vc.FastPoint, length1)
	for i := 0; i < length1; i++ {
		p.Sub1.TL[i] = getPointCompressed(data[offset:])
		offset += 33
	}
	for i := 0; i < length1; i++ {
		p.Sub1.TR[i] = getPointCompressed(data[offset:])
		offset += 33
	}
	p.Sub1.BigC = getPointCompressed(data[offset:])
	offset += 33
	p.Sub1.BigCPrime = getPointCompressed(data[offset:])
	offset += 33
	p.Sub1.E1 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.E2 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub1.O = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub2 = new(SubProof2)
	length2 := int(math.Log2(float64(D * BPrime)))
	p.Sub2.TL = make([]vc.FastPoint, length2)
	p.Sub2.TR = make([]vc.FastPoint, length2)
	for i := 0; i < length2; i++ {
		p.Sub2.TL[i] = getPointCompressed(data[offset:])
		offset += 33
	}
	for i := 0; i < length2; i++ {
		p.Sub2.TR[i] = getPointCompressed(data[offset:])
		offset += 33
	}
	p.Sub2.BigC = getPointCompressed(data[offset:])
	offset += 33
	p.Sub2.E1 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	p.Sub2.E2 = new(big.Int).SetBytes(data[offset : offset+32])
	offset += 32
	if offset != len(data) {
		panic("size error")
	}

	err = nil
	return
}

func SerializeSigList(sigs []*adaptor.Signature) []byte {
	data := make([]byte, YNumber*(32+32))
	offset := 0
	for i := int32(0); i < YNumber; i++ {
		sigs[i].E.FillBytes(data[offset : offset+32])
		sigs[i].S.FillBytes(data[offset+32 : offset+64])
		offset += 64
	}
	if offset != len(data) {
		panic("SigList size error")
	}
	return data
}

func DeserializeSigList(data []byte) (sigs []*adaptor.Signature, err error) {
	defer func() {
		fatal := recover()
		if fatal != nil {
			err = fmt.Errorf("SigList deserliazation error\n")
		}
	}()
	sigs = make([]*adaptor.Signature, YNumber)
	offset := 0
	for i := int32(0); i < YNumber; i++ {
		sigs[i] = new(adaptor.Signature)
		sigs[i].E = new(big.Int).SetBytes(data[offset : offset+32])
		sigs[i].S = new(big.Int).SetBytes(data[offset+32 : offset+64])
		offset += 64
	}
	if offset != len(data) {
		panic("size error")
	}
	err = nil
	return
}

func SerializeYListCompressed(yPoints []vc.FastPoint) []byte {
	data := make([]byte, YNumber*33)
	offset := 0
	for i := int32(0); i < YNumber; i++ {
		storePointCompressed(data[offset:], yPoints[i])
		offset += 33
	}
	if offset != len(data) {
		panic("YList size error")
	}
	return data
}

func SerializeYList(yPoints []vc.FastPoint) []byte {
	data := make([]byte, YNumber*64)
	offset := 0
	for i := int32(0); i < YNumber; i++ {
		storePoint(data[offset:], yPoints[i])
		offset += 64
	}
	if offset != len(data) {
		panic("YList size error")
	}
	return data
}

func DeserializeYList(data []byte) (yPoints []vc.FastPoint, err error) {
	defer func() {
		fatal := recover()
		if fatal != nil {
			err = fmt.Errorf("YList deserliazation error\n")
		}
	}()

	yPoints = make([]vc.FastPoint, YNumber)
	offset := 0
	for i := int32(0); i < YNumber; i++ {
		yPoints[i] = getPoint(data[offset:])
		offset += 64
	}
	if offset != len(data) {
		panic("size error")
	}
	err = nil
	return
}

func DeserializeYListCompressed(data []byte) (yPoints []vc.FastPoint, err error) {
	defer func() {
		fatal := recover()
		if fatal != nil {
			err = fmt.Errorf("YList deserliazation error\n")
		}
	}()

	yPoints = make([]vc.FastPoint, YNumber)
	offset := 0
	for i := int32(0); i < YNumber; i++ {
		yPoints[i] = getPointCompressed(data[offset:])
		offset += 33
	}
	if offset != len(data) {
		panic("size error")
	}
	err = nil
	return
}
