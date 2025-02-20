package secp256k1_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"volley/secp256k1"
)

func ExampleSignAndVerifyHash() {
	// 初始化预计算数据
	secp256k1.InitNAFTables(9)

	// 获取曲线
	curve := secp256k1.Curve()

	// 使用crypto/ecdsa包中的接口产生公私钥
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// 使用sha256进行Hash
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)

	// 使用crypto/ecdsa包中的接口执行签名
	r, s, err := secp256k1.SignHash(rand.Reader, pri, digest[:])
	if err != nil {
		panic(err)
	}

	// 获取公钥
	pub := &pri.PublicKey
	verified := secp256k1.VerifyHash(pub, digest[:], r, s, nil)

	fmt.Println(verified)
	// Output: true
}

func ExampleSignAndVerify() {
	// 初始化预计算数据
	secp256k1.InitNAFTables(9)

	// 获取曲线
	curve := secp256k1.Curve()

	// 使用crypto/ecdsa包中的接口产生公私钥
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// 使用sha256进行Hash
	msg := []byte("hello world")

	// 使用crypto/ecdsa包中的接口执行签名
	sig, err := secp256k1.SignECDSA(rand.Reader, pri, msg, sha256.New())
	if err != nil {
		panic(err)
	}

	// 获取公钥
	pub := &pri.PublicKey
	verified := secp256k1.VerifyECDSA(pub, msg, sig, sha256.New(), nil)

	fmt.Println(verified)
	// Output: true
}

func ExampleSignAndVerifyOnPrecomputes() {
	// 初始化预计算数据
	secp256k1.InitNAFTables(9)

	// 获取曲线
	curve := secp256k1.Curve()

	// 使用crypto/ecdsa包中的接口产生公私钥
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// 使用sha256进行Hash
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)

	// 使用SignHash执行签名
	r, s, err := secp256k1.SignHash(rand.Reader, pri, digest[:])
	if err != nil {
		panic(err)
	}

	// 获取公钥
	pub := &pri.PublicKey

	// 对公钥产生预计算数据
	precomputes := secp256k1.ComputePrecomputesForPoint(pub.X, pub.Y)

	// 使用VerifyHash进行验签
	verified := secp256k1.VerifyHash(pub, digest[:], r, s, precomputes)

	fmt.Println(verified)
	// Output: true
}

func ExampleSignAndVerifyUsingStdInterface() {
	// 初始化预计算数据
	secp256k1.InitNAFTables(8)

	// 获取曲线
	curve := secp256k1.Curve()

	// 使用crypto/ecdsa包中的接口产生公私钥
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// 使用sha256进行Hash
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)

	// 使用crypto/ecdsa包中的接口执行签名
	r, s, err := ecdsa.Sign(rand.Reader, pri, digest[:])
	if err != nil {
		panic(err)
	}

	// 获取公钥
	pub := &pri.PublicKey
	verified := ecdsa.Verify(pub, digest[:], r, s)

	fmt.Println(verified)
	// Output: true
}

func ExampleSignAndVerifyASN1UsingStdInterface() {
	// 初始化预计算数据
	secp256k1.InitNAFTables(7)

	// 获取曲线
	curve := secp256k1.Curve()

	// 使用crypto/ecdsa包中的接口产生公私钥
	pri, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// 使用SM3进行Hash
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)

	// 使用crypto/ecdsa包中的接口执行签名
	sigBytes, err := ecdsa.SignASN1(rand.Reader, pri, digest[:])
	if err != nil {
		panic(err)
	}

	// 获取公钥
	pub := &pri.PublicKey
	verified := ecdsa.VerifyASN1(pub, digest[:], sigBytes)

	fmt.Println(verified)
	// Output: true
}
