package lpr

import (
	"encoding/binary"
	"fmt"
	"io"
)

func GenSecret(d int32, random io.Reader) (*PrivateKey, error) {
	data, err := GenerateR2(d, random)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		Data: data,
	}, nil
}

func GenerateR2(d int32, random io.Reader) ([]int32, error) {
	samples := make([]byte, d)
	n, err := random.Read(samples)
	if err != nil {
		return nil, err
	}
	if n != int(d) {
		return nil, fmt.Errorf(fmt.Sprintf("No enough data: %d", n))
	}
	result := make([]int32, d)
	for i, s := range samples {
		result[i] = int32(s)%2 - 1
	}
	return result, nil
}

//func GenerateGaussian(d int32, min, max int32, random io.Reader) ([]int32, error) {
//	result := make([]int32, d)
//
//	seedBytes := make([]byte, 64)
//	_, err := random.Read(seedBytes)
//	if err != nil {
//		return nil, err
//	}
//	mean := 0.0
//	stdDev := 1.0
//
//	normal := distuv.Normal{
//		Mu:    mean,
//		Sigma: stdDev,
//		Src:   rand.NewSource(binary.BigEndian.Uint64(seedBytes)), // 随机种子
//	}
//
//	for i := 0; i < int(d); i++ {
//		result[i] = int32(normal.Rand())
//		if result[i] > max {
//			result[i] = max
//		}
//		if result[i] < min {
//			result[i] = min
//		}
//	}
//	return result, nil
//}

func GenerateRq(d int32, q int32, random io.Reader) ([]int32, error) {
	samples := make([]byte, d*4)
	n, err := random.Read(samples)
	if err != nil {
		return nil, err
	}
	if n != int(d)*4 {
		return nil, fmt.Errorf(fmt.Sprintf("No enough data: %d", n))
	}
	result := make([]int32, d)
	for i := int32(0); i < d; i++ {
		sample := int32(binary.LittleEndian.Uint32(samples[i*4:]) % uint32(q))
		result[i] = sample - (q / 2)
	}
	return result, nil
}

func GenPublicKey(secret *PrivateKey, q int32, random io.Reader) (*PublicKey, error) {
	a, err := GenerateRq(int32(len(secret.Data)), q, random)
	if err != nil {
		return nil, err
	}

	e, err := GenerateR2(int32(len(secret.Data)), random)
	if err != nil {
		return nil, err
	}

	pk0 := PolyNeg(PolyAdd(PolyMul(secret.Data, a, q), e, q), q)
	return &PublicKey{
		PK0: pk0,
		PK1: a,
	}, nil
}
