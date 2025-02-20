package protocol

import (
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"volley/lpr"
)

func GenKeyRLWE(privatePath, publicPath string, random io.Reader) error {
	secretKey, err := lpr.GenSecret(D, random)
	if err != nil {
		return err
	}
	publicKey, err := lpr.GenPublicKey(secretKey, Q, random)
	if err != nil {
		return err
	}
	secretBytes := make([]byte, D)
	for i, d := range secretKey.Data {
		secretBytes[i] = byte(d)
	}
	err = os.WriteFile(privatePath, secretBytes, os.ModePerm)
	if err != nil {
		return err
	}
	publicBytes := publicKey.Serialize(Q)
	err = os.WriteFile(publicPath, publicBytes, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func GenKey(privatePath, publicPath string, random io.Reader) error {
	n1 := fastCurve.Params().N
	k, err := rand.Int(random, n1)
	if err != nil {
		return err
	}
	p := fastCurve.FastBaseScalar(k.Bytes())
	secretBytes := make([]byte, 96)
	k.FillBytes(secretBytes[0:32])
	publicBytes := make([]byte, 64)
	px, py := p.Back()
	px.FillBytes(publicBytes[0:32])
	py.FillBytes(publicBytes[32:64])
	px.FillBytes(secretBytes[32:64])
	py.FillBytes(secretBytes[64:96])
	err = os.WriteFile(privatePath, secretBytes, os.ModePerm)
	if err != nil {
		return err
	}
	err = os.WriteFile(publicPath, publicBytes, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func Setup(genPath, precomputesPath string, random io.Reader) (err error) {
	genFile, err := os.Create(genPath)
	if err != nil {
		return err
	}
	defer func() {
		fErr := genFile.Close()
		if err == nil {
			err = fErr
		}
	}()

	preFile, err := os.Create(precomputesPath)
	if err != nil {
		return err
	}
	defer func() {
		fErr := preFile.Close()
		if err == nil {
			err = fErr
		}
	}()

	n1 := fastCurve.Params().N
	hSum1 := fastCurve.NewPoint()
	hSum2 := fastCurve.NewPoint()
	var k *big.Int
	pointBytes := make([]byte, 64)

	for i := int32(0); i < L; i++ {
		k, err = rand.Int(random, n1)
		if err != nil {
			return
		}
		point := fastCurve.FastBaseScalar(k.Bytes())
		px, py := point.Back()
		px.FillBytes(pointBytes[0:32])
		py.FillBytes(pointBytes[32:64])
		precomputes := point.ExportTable(true)
		_, err = genFile.Write(pointBytes)
		if err != nil {
			return
		}
		_, err = preFile.Write(precomputes)
		if err != nil {
			return
		}
	}

	for i := int32(0); i < L; i++ {
		k, err = rand.Int(random, n1)
		if err != nil {
			return err
		}
		point := fastCurve.FastBaseScalar(k.Bytes())
		px, py := point.Back()
		px.FillBytes(pointBytes[0:32])
		py.FillBytes(pointBytes[32:64])
		precomputes := point.ExportTable(true)
		_, err = genFile.Write(pointBytes)
		if err != nil {
			return
		}
		_, err = preFile.Write(precomputes)
		if err != nil {
			return
		}
		if i >= 3*D*B && i < 3*D*B+D*BPrime {
			fastCurve.FastPointAdd(hSum2, hSum2, point)
		} else {
			fastCurve.FastPointAdd(hSum1, hSum1, point)
		}
	}

	k, err = rand.Int(random, n1)
	if err != nil {
		return
	}
	u := fastCurve.FastBaseScalar(k.Bytes())
	ux, uy := u.Back()
	ux.FillBytes(pointBytes[0:32])
	uy.FillBytes(pointBytes[32:64])
	_, err = genFile.Write(pointBytes)
	if err != nil {
		return
	}
	hx, hy := hSum1.Back()
	hx.FillBytes(pointBytes[0:32])
	hy.FillBytes(pointBytes[32:64])
	_, err = preFile.Write(pointBytes)
	if err != nil {
		return
	}
	hx, hy = hSum2.Back()
	hx.FillBytes(pointBytes[0:32])
	hy.FillBytes(pointBytes[32:64])
	_, err = preFile.Write(pointBytes)
	if err != nil {
		return
	}
	err = nil
	return
}
