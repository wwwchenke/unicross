package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"time"
	"volley/adaptor"
	vc "volley/curve"
	"volley/lpr"
	"volley/protocol"
	"volley/secp256k1"
)

func main() {
	secp256k1.InitNAFTables(9)
	protocol.SetCurve(secp256k1.FastCurve())
	adaptor.SetCurve(secp256k1.FastCurve())

	prefix := "./testdata"

	setup, steps, threadNum, index, err := ParseArgument(os.Args)
	if err != nil {
		return
	}

	protocol.SetCoreNum(threadNum)
	random := rand.Reader
	if setup {
		_ = os.MkdirAll(prefix+"/public", os.ModePerm)
		_ = os.MkdirAll(prefix+"/tumbler", os.ModePerm)
		_ = os.MkdirAll(prefix+"/bob", os.ModePerm)
		_ = os.MkdirAll(prefix+"/alice", os.ModePerm)

		start := time.Now()
		err = protocol.Setup(prefix+"/public/generator.dat", prefix+"/public/precomputes.dat", rand.Reader)
		if err != nil {
			panic(err)
		}
		fmt.Println("Time cost on initializing generator and precomputes: ", time.Since(start))

		err = protocol.GenKey(prefix+"/alice/alice_private.dat", prefix+"/public/alice_public.dat", random)
		if err != nil {
			panic(err)
		}
		err = protocol.GenKey(prefix+"/bob/bob_private.dat", prefix+"/public/bob_public.dat", random)
		if err != nil {
			panic(err)
		}
		err = protocol.GenKey(prefix+"/tumbler/tumbler_private.dat", prefix+"/public/tumbler_public.dat", random)
		if err != nil {
			panic(err)
		}
		fmt.Println("Private/Public key of Tumbler/Alice/Bob generated(secp256k1)")
		err = protocol.GenKeyRLWE(prefix+"/tumbler/tumbler_rlwe_private.dat",
			prefix+"/public/tumbler_rlwe_public.dat", random)
		if err != nil {
			panic(err)
		}
		fmt.Println("Private/Public key of Tumbler generated(RLWE)")
	}

	if !(steps[0] || steps[1] || steps[2] || steps[3] || steps[4] || steps[5]) {
		return
	}

	var tumbler *protocol.Tumbler
	var bob *protocol.Bob
	var alice *protocol.Alice
	tx := []byte("This is the tx transferred from tumbler to bob")
	tx2 := []byte("This is the tx transferred from alice to tumbler")

	generatorFile := prefix + "/public/generator.dat"
	precomputesFile := prefix + "/public/precomputes.dat"
	tumblerPublic := prefix + "/public/tumbler_public.dat"
	alicePublic := prefix + "/public/alice_public.dat"
	bobPublic := prefix + "/public/bob_public.dat"
	tumblerPrivate := prefix + "/tumbler/tumbler_private.dat"
	bobPrivate := prefix + "/bob/bob_private.dat"
	alicePrivate := prefix + "/alice/alice_private.dat"
	rlweSecret := prefix + "/tumbler/tumbler_rlwe_private.dat"
	rlwePublic := prefix + "/public/tumbler_rlwe_public.dat"

	spaceString := "Data Transferred:\n"
	fmt.Println("Time Cost:")
	if steps[0] {
		tumbler = new(protocol.Tumbler)
		err = tumbler.Init(generatorFile, precomputesFile, tumblerPrivate, alicePublic, bobPublic,
			rlweSecret, rlwePublic)
		if err != nil {
			panic(err)
		}
		start := time.Now()
		proof, y, rlweCiphertext, step1Err := tumbler.Step1x(random)
		if step1Err != nil {
			panic(step1Err)
		}
		d1 := time.Since(start)

		start = time.Now()
		sigs, step1Err := tumbler.Step1y(tx, y, random)
		if step1Err != nil {
			panic(step1Err)
		}
		d2 := time.Since(start)

		start = time.Now()
		proofBytes := proof.SerializeCompressed()
		cipherBytes := rlweCiphertext.Serialize(protocol.Q)

		yListBytes := protocol.SerializeYListCompressed(y)
		sigListBytes := protocol.SerializeSigList(sigs)
		d3 := time.Since(start)
		fmt.Println("Step1: Time cost in all", d1+d2+d3)
		fmt.Printf("\t--Puzzle creation and Nizk Proof generation: %v\n", d1)
		fmt.Printf("\t--Adaptor Signature generation: %v\n", d2)
		fmt.Printf("\t--Serialization of data to send: %v\n", d3)

		spaceString += "Step1: Data transferred from Tumbler to Bob: "
		spaceString += fmt.Sprintf("%d bytes in all\n", len(proofBytes)+len(cipherBytes)+len(yListBytes)+len(sigListBytes))
		spaceString += fmt.Sprintf("\t--Nizk Proof: %d bytes\n", len(proofBytes))
		spaceString += fmt.Sprintf("\t--RLWE Ciphertext: %d bytes\n", len(cipherBytes))
		spaceString += fmt.Sprintf("\t--Y List: %d bytes\n", len(yListBytes))
		spaceString += fmt.Sprintf("\t--Sig List: %d bytes\n", len(sigListBytes))

		err = os.WriteFile(prefix+"/bob/nizk_proof.dat", proofBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(prefix+"/bob/rlwe_ciphertext.dat", cipherBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(prefix+"/bob/y_list.dat", yListBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(prefix+"/bob/sig_list.dat", sigListBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}

	}

	if steps[1] {
		bob = new(protocol.Bob)
		err = bob.Init(generatorFile, precomputesFile, tumblerPublic, alicePublic, bobPrivate, rlwePublic)
		if err != nil {
			panic(err)
		}
		start := time.Now()
		proof := new(protocol.Proof)
		var proofBytes, cipherBytes, yListBytes, sigListBytes []byte
		proofBytes, err = os.ReadFile(prefix + "/bob/nizk_proof.dat")
		if err != nil {
			panic(err)
		}
		err = proof.DeserializeCompressed(proofBytes)
		if err != nil {
			panic(err)
		}
		cipherBytes, err = os.ReadFile(prefix + "/bob/rlwe_ciphertext.dat")
		if err != nil {
			panic(err)
		}
		rlweCipher := new(lpr.Ciphertext)
		err = rlweCipher.Deserialize(cipherBytes, protocol.D, protocol.Q)
		if err != nil {
			panic(err)
		}
		yListBytes, err = os.ReadFile(prefix + "/bob/y_list.dat")
		if err != nil {
			panic(err)
		}
		sigListBytes, err = os.ReadFile(prefix + "/bob/sig_list.dat")
		if err != nil {
			panic(err)
		}
		var yPoints []vc.FastPoint
		var sigs []*adaptor.Signature
		yPoints, err = protocol.DeserializeYListCompressed(yListBytes)
		if err != nil {
			panic(err)
		}
		sigs, err = protocol.DeserializeSigList(sigListBytes)
		if err != nil {
			panic(err)
		}
		d1 := time.Since(start)

		start = time.Now()
		newCiphertext, yPrime, step2Err := bob.Step2(tx, proof, rlweCipher, yPoints, sigs[index], index, rand.Reader)
		if step2Err != nil {
			panic(step2Err)
		}
		d2 := time.Since(start)
		fmt.Println("Nizk Proof verified")
		start = time.Now()

		lweData := make([]byte, (64+int(protocol.D))*2)
		for i := 0; i < 64; i++ {
			binary.BigEndian.PutUint16(lweData[2*i:], uint16(newCiphertext.CT0[index*64+i]))
		}
		for i := 0; i < int(protocol.D); i++ {
			binary.BigEndian.PutUint16(lweData[2*64+2*i:], uint16(newCiphertext.CT1[i]))
		}

		yPrimeData := make([]byte, 33)
		x, y := yPrime.Back()
		x.FillBytes(yPrimeData[1:33])
		yPrimeData[0] = 0x02 | byte(y.Bit(0))
		d3 := time.Since(start)
		fmt.Println("Step2: Time cost in all", d1+d2+d3)
		fmt.Printf("\t--Deserialization of data received: %v\n", d1)
		fmt.Printf("\t--Nizk Proof and signature verification, ciphertext randomization, : %v\n", d2)
		fmt.Printf("\t--Serialization of data to send: %v\n", d3)
		err = os.WriteFile(fmt.Sprintf("%s/alice/y_prime_%d.dat", prefix, index), yPrimeData, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(fmt.Sprintf("%s/alice/lwe_ciphertext_%d.dat", prefix, index), lweData, os.ModePerm)
		if err != nil {
			panic(err)
		}

		err = bob.SaveState(fmt.Sprintf("%s/bob/rdm_plaintexttext_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		spaceString += "Step2: Data transferred from Bob to Alice: "
		spaceString += fmt.Sprintf("%d bytes in all\n", len(lweData)+len(yPrimeData))
		spaceString += fmt.Sprintf("\t--Y': %d bytes\n", len(yPrimeData))
		spaceString += fmt.Sprintf("\t--Partial LWE Ciphertext: %d bytes\n", len(lweData))
	}

	if steps[2] {
		alice = new(protocol.Alice)
		err = alice.Init(tumblerPublic, alicePrivate, bobPublic)
		if err != nil {
			panic(err)
		}
		var lweData, yPrimeBytes []byte
		start := time.Now()
		lweData, err = os.ReadFile(fmt.Sprintf("%s/alice/lwe_ciphertext_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		yPrimeBytes, err = os.ReadFile(fmt.Sprintf("%s/alice/y_prime_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		yPrime := protocol.GetPointCompressed(yPrimeBytes)
		d1 := time.Since(start)
		start = time.Now()
		var sigAlice *adaptor.Signature
		sigAlice, err = alice.Step3(tx2, yPrime, random)
		if err != nil {
			panic(err)
		}
		d2 := time.Since(start)
		start = time.Now()
		sigBytes := make([]byte, 64)
		sigAlice.E.FillBytes(sigBytes[0:32])
		sigAlice.S.FillBytes(sigBytes[32:64])
		d3 := time.Since(start)
		fmt.Println("Step3: Time cost in all", d1+d2+d3)
		fmt.Printf("\t--Deserialization of data received: %v\n", d1)
		fmt.Printf("\t--Adaptor signature generation, : %v\n", d2)
		fmt.Printf("\t--Serialization of data to send: %v\n", d3)

		err = os.WriteFile(fmt.Sprintf("%s/tumbler/sig_alice_%d.dat", prefix, index), sigBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(fmt.Sprintf("%s/tumbler/y_prime_%d.dat", prefix, index), yPrimeBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(fmt.Sprintf("%s/tumbler/lwe_ciphertext_%d.dat", prefix, index), lweData, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = alice.SaveState(fmt.Sprintf("%s/alice/sig_alice_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		spaceString += "Step3: Data transferred from Alice to Tumbler: "
		spaceString += fmt.Sprintf("%d bytes in all\n", len(lweData)+len(yPrimeBytes)+len(sigBytes))
		spaceString += fmt.Sprintf("\t--Y': %d bytes\n", len(yPrimeBytes))
		spaceString += fmt.Sprintf("\t--Partial LWE Ciphertext: %d bytes\n", len(lweData))
	}

	if steps[3] {
		if tumbler == nil {
			tumbler = new(protocol.Tumbler)
			err = tumbler.Init(generatorFile, precomputesFile, tumblerPrivate, alicePublic, bobPublic,
				rlweSecret, rlwePublic)
			if err != nil {
				panic(err)
			}
		}

		var lweData, yPrimeBytes, sigAliceBytes []byte

		lweData, err = os.ReadFile(fmt.Sprintf("%s/tumbler/lwe_ciphertext_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		yPrimeBytes, err = os.ReadFile(fmt.Sprintf("%s/tumbler/y_prime_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		sigAliceBytes, err = os.ReadFile(fmt.Sprintf("%s/tumbler/sig_alice_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}

		start := time.Now()
		newCiphertext := new(lpr.Ciphertext)
		newCiphertext.CT0 = make([]int32, protocol.D)
		newCiphertext.CT1 = make([]int32, protocol.D)
		for i := 0; i < 64; i++ {
			value := int32(binary.BigEndian.Uint16(lweData[2*i:]))
			if value >= protocol.Q/2 {
				value -= protocol.Q
			}
			newCiphertext.CT0[index*64+i] = value
		}
		for i := 0; i < int(protocol.D); i++ {
			value := int32(binary.BigEndian.Uint16(lweData[2*64+2*i:]))
			if value >= protocol.Q/2 {
				value -= protocol.Q
			}
			newCiphertext.CT1[i] = value
		}

		lweCipherList := make([]*lpr.LWECiphertext, 64)
		for i := 0; i < 64; i++ {
			lweCipherList[i] = lpr.Extract(newCiphertext, protocol.Q, index*64+i)
		}

		yPrime := protocol.GetPointCompressed(yPrimeBytes)
		sigAlice := new(adaptor.Signature)
		sigAlice.E = new(big.Int).SetBytes(sigAliceBytes[0:32])
		sigAlice.S = new(big.Int).SetBytes(sigAliceBytes[32:64])
		d1 := time.Since(start)
		start = time.Now()
		var sigAliceRecovered *adaptor.Signature
		sigAliceRecovered, err = tumbler.Step4(tx2, sigAlice, yPrime, lweCipherList)
		if err != nil {
			panic(err)
		}
		d2 := time.Since(start)
		start = time.Now()
		sigBytes := make([]byte, 64)
		sigAliceRecovered.E.FillBytes(sigBytes[0:32])
		sigAliceRecovered.S.FillBytes(sigBytes[32:64])
		d3 := time.Since(start)
		fmt.Println("Step4: Time cost in all", d1+d2+d3)
		fmt.Printf("\t--Deserialization of data received: %v\n", d1)
		fmt.Printf("\t--Adaptor Signature and Ciphertext verification, Alice's Signature Recovery : %v\n", d2)
		fmt.Printf("\t--Serialization of data to send: %v\n", d3)

		err = os.WriteFile(fmt.Sprintf("%s/alice/sig_alice_recovered_%d.dat", prefix, index), sigBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}

		if adaptor.SchnorrVerify(sigAliceRecovered, tx2, tumbler.AlicePublic, sha256.New()) {
			fmt.Println("Recovered signature of alice verified")
		} else {
			panic("Recovered signature of alice not verified")
		}

		spaceString += "Step4: Data transferred from Tumbler to Alice: "
		spaceString += fmt.Sprintf("%d bytes (Alice's Recovered Signature)\n", len(sigBytes))
	}

	if steps[4] {
		if alice == nil {
			alice = new(protocol.Alice)
			err = alice.Init(tumblerPublic, alicePrivate, bobPublic)
			if err != nil {
				panic(err)
			}
		}
		err = alice.LoadStateIfNeeded(fmt.Sprintf("%s/alice/sig_alice_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		var sigBytes []byte
		sigBytes, err = os.ReadFile(fmt.Sprintf("%s/alice/sig_alice_recovered_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		start := time.Now()
		sigAliceRecovered := &adaptor.Signature{
			E: new(big.Int).SetBytes(sigBytes[0:32]),
			S: new(big.Int).SetBytes(sigBytes[32:64]),
		}
		d1 := time.Since(start)
		start = time.Now()
		plain := alice.Step5(sigAliceRecovered)
		d2 := time.Since(start)
		start = time.Now()
		plainBytes := make([]byte, 32)
		plain.FillBytes(plainBytes)
		d3 := time.Since(start)
		fmt.Println("Step5: Time cost in all", d1+d2+d3)
		fmt.Printf("\t--Deserialization of data received: %v\n", d1)
		fmt.Printf("\t--Patial randomized plaintext calculation : %v\n", d2)
		fmt.Printf("\t--Serialization of data to send: %v\n", d3)
		err = os.WriteFile(fmt.Sprintf("%s/bob/puzzle_plaintext_%d.dat", prefix, index), plainBytes, os.ModePerm)
		if err != nil {
			panic(err)
		}
		spaceString += "Step5: Data transferred from Alice to Bob: "
		spaceString += fmt.Sprintf("%d bytes (Partial Randomized Plaintext)\n", len(plainBytes))
	}

	if steps[5] {
		if bob == nil {
			bob = new(protocol.Bob)
			err = bob.Init(generatorFile, precomputesFile, tumblerPublic, alicePublic, bobPrivate, rlwePublic)
			if err != nil {
				panic(err)
			}
		}

		err = bob.LoadStateIfNeeded(fmt.Sprintf("%s/bob/rdm_plaintexttext_%d.dat", prefix, index),
			prefix+"/bob/sig_list.dat", index)
		if err != nil {
			panic(err)
		}
		var plainNumBytes []byte
		plainNumBytes, err = os.ReadFile(fmt.Sprintf("%s/bob/puzzle_plaintext_%d.dat", prefix, index))
		if err != nil {
			panic(err)
		}
		start := time.Now()
		plainNum := new(big.Int).SetBytes(plainNumBytes)
		d1 := time.Since(start)
		start = time.Now()
		var sigTumblerReal *adaptor.Signature
		sigTumblerReal = bob.Step6(plainNum)
		d2 := time.Since(start)
		fmt.Println("Step6: Time cost in all", d1+d2)
		fmt.Printf("\t--Deserialization of data received: %v\n", d1)
		fmt.Printf("\t--Tumbler's Signature recovery : %v\n", d2)
		if adaptor.SchnorrVerify(sigTumblerReal, tx, bob.TumblerPublic, sha256.New()) {
			fmt.Println("Recovered signature of Tumbler verified")
		} else {
			panic("Recovered signature of Tumbler not verified")
		}
	}

	fmt.Println()
	fmt.Println(spaceString)
}
