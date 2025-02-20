package protocol

import (
	"crypto/sha256"
	"io"
	"math/big"
	"os"
	"volley/adaptor"
	vc "volley/curve"
)

type Alice struct {
	TumblerPublic vc.FastPoint
	BobPublic     vc.FastPoint

	Secret *big.Int
	Public vc.FastPoint

	adaptorSig *adaptor.Signature
}

func (alice *Alice) Init(tumblerPath, secretPath, bobPath string) error {
	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	alice.Secret = new(big.Int).SetBytes(secretBytes[0:32])
	publicX := new(big.Int).SetBytes(secretBytes[32:64])
	publicY := new(big.Int).SetBytes(secretBytes[64:96])
	alice.Public = fastCurve.NewPoint()
	alice.Public.From(publicX, publicY)

	tumblerBytes, err := os.ReadFile(tumblerPath)
	if err != nil {
		return err
	}
	publicX = new(big.Int).SetBytes(tumblerBytes[0:32])
	publicY = new(big.Int).SetBytes(tumblerBytes[32:64])
	alice.TumblerPublic = fastCurve.NewPoint()
	alice.TumblerPublic.From(publicX, publicY)

	bobBytes, err := os.ReadFile(bobPath)
	if err != nil {
		return err
	}
	publicX = new(big.Int).SetBytes(bobBytes[0:32])
	publicY = new(big.Int).SetBytes(bobBytes[32:64])
	alice.BobPublic = fastCurve.NewPoint()
	alice.BobPublic.From(publicX, publicY)
	return nil
}

func (alice *Alice) Step3(tx []byte, yPrime vc.FastPoint, random io.Reader) (*adaptor.Signature, error) {
	sig, err := adaptor.SchnorrSignAdaptor(tx, yPrime, alice.Secret, sha256.New(), random)
	if err != nil {
		return nil, err
	}
	alice.adaptorSig = sig
	return sig, nil
}

func (alice *Alice) Step5(sigAliceReal *adaptor.Signature) *big.Int {
	plain := new(big.Int).Sub(sigAliceReal.S, alice.adaptorSig.S)
	plain.Mod(plain, fastCurve.Params().N)
	return plain
}

func (alice *Alice) SaveState(sigPath string) error {
	sigBytes := make([]byte, 64)
	alice.adaptorSig.E.FillBytes(sigBytes[0:32])
	alice.adaptorSig.S.FillBytes(sigBytes[32:64])
	return os.WriteFile(sigPath, sigBytes, os.ModePerm)
}

func (alice *Alice) LoadStateIfNeeded(sigPath string) error {
	if alice.adaptorSig != nil {
		return nil
	}
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	alice.adaptorSig = new(adaptor.Signature)
	alice.adaptorSig.E = new(big.Int).SetBytes(sigBytes[0:32])
	alice.adaptorSig.S = new(big.Int).SetBytes(sigBytes[32:64])
	return nil
}
