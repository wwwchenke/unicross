package secp256k1

import (
	"fmt"
	"math/big"
)

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out []uint64, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}

func maybeReduceModP(in *big.Int) *big.Int {
	if in.Cmp(p256k1Curve.params.P) < 0 {
		return in
	}
	return new(big.Int).Mod(in, p256k1Curve.params.P)
}

// p256GetScalar endian-swaps the big-endian scalar value from in and writes it
// to out. If the scalar is equal or greater than the order of the group, it's
// reduced modulo that order.
func sm2CurveGetScalar(out []uint64, in []byte) {
	n := new(big.Int).SetBytes(in)

	if n.Cmp(p256k1Curve.params.N) >= 0 {
		n.Mod(n, p256k1Curve.params.N)
	}
	fromBig(out, n)
}

func boothW5(in uint) (int, int) {
	var s uint = ^((in >> 5) - 1)
	var d uint = (1 << 6) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW6(in uint) (int, int) {
	var s uint = ^((in >> 6) - 1)
	var d uint = (1 << 7) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW7(in uint) (int, int) {
	var s uint = ^((in >> 7) - 1)
	var d uint = (1 << 8) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW8(in uint) (int, int) {
	var s uint = ^((in >> 8) - 1)
	var d uint = (1 << 9) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW9(in uint) (int, int) {
	var s uint = ^((in >> 9) - 1)
	var d uint = (1 << 10) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

// scalarIsZero returns 1 if scalar represents the zero value, and zero
// otherwise.
func scalarIsZero(scalar []uint64) bool {
	return (scalar[0] | scalar[1] | scalar[2] | scalar[3]) == 0
}

// MarshalSig 将Signature转换为ASN1标准
func MarshalSig(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rLength := len(rBytes)
	sLength := len(sBytes)
	length := rLength + sLength + 4
	if rBytes[0]&0x80 != 0 {
		length++
		rLength++
	}
	if sBytes[0]&0x80 != 0 {
		length++
		sLength++
	}
	sig := make([]byte, length+2)
	sig[0] = 0x30
	sig[1] = byte(length)
	sig[2] = 0x02
	sig[3] = byte(rLength)
	offset := 4 + rLength - len(rBytes)
	copy(sig[offset:], rBytes)
	offset += len(rBytes)
	sig[offset] = 0x02
	sig[offset+1] = byte(sLength)
	offset += 2 + sLength - len(sBytes)
	copy(sig[offset:], sBytes)
	return sig
}

// UnmarshalSig 对ASN1编码的签名进行解码
func UnmarshalSig(sig []byte) (r, s *big.Int, err error) {
	defer func() {
		ex := recover()
		if ex != nil {
			s = nil
			err = fmt.Errorf("Signature length error fatal\n")
		}
	}()

	if sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("Signature is not a sequence\n")
	}
	length := int(sig[1])
	if length+2 != len(sig) {
		return nil, nil, fmt.Errorf("Signature length error\n")
	}
	if sig[2] != 0x02 {
		return nil, nil, fmt.Errorf("R of signature is not an integer\n")
	}
	rLength := int(sig[3])
	rBytes := sig[4 : 4+rLength]
	if (rBytes[0] & 0x80) != 0 {
		return nil, nil, fmt.Errorf("R of signature is negative\n")
	}
	r = new(big.Int).SetBytes(rBytes)
	offset := 4 + rLength
	if sig[offset] != 0x02 {
		return nil, nil, fmt.Errorf("S of signature is not an integer\n")
	}
	sLength := int(sig[offset+1])
	offset += 2
	sBytes := sig[offset : offset+sLength]
	if (sBytes[0] & 0x80) != 0 {
		return nil, nil, fmt.Errorf("S of signature is negative\n")
	}
	s = new(big.Int).SetBytes(sBytes)
	if offset+sLength != len(sig) {
		return nil, nil, fmt.Errorf("Signature length error\n")
	}

	return
}
