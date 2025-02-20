package adaptor_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"volley/adaptor"
	"volley/secp256k1"
)

func TestAdaptorSig(t *testing.T) {
	secp256k1.InitNAFTables(9)
	adaptor.SetCurve(secp256k1.FastCurve())
	fastCurve := secp256k1.FastCurve()

	for i := 0; i < 100000; i++ {
		msg := make([]byte, 61)
		rand.Read(msg)

		secret, err := rand.Int(rand.Reader, fastCurve.Params().N)
		if err != nil {
			t.Fatal(err)
		}
		public := fastCurve.FastBaseScalar(secret.Bytes())
		d, err := rand.Int(rand.Reader, fastCurve.Params().N)
		if err != nil {
			t.Fatal(err)
		}
		//yX, yY := fastCurve.ScalarBaseMult(d.Bytes())
		//yPoint := &adaptor.Point{
		//	X: yX,
		//	Y: yY,
		//}
		yPoint := fastCurve.FastBaseScalar(d.Bytes())

		sig, err := adaptor.SchnorrSignAdaptor(msg, yPoint, secret, sha256.New(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		verified := adaptor.SchnorrPreVerifyAdaptor(sig, msg, yPoint, public, sha256.New())
		if !verified {
			t.Fatal("Not verified")
		}
	}
}
