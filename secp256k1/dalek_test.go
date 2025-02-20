package secp256k1

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestDalek(t *testing.T) {
	data := make([]byte, 32)
	count := 0
	for x := 0; x < 1000000; x++ {
		rand.Read(data)

		sNaf := nonAdjacentFormBE256(data, 5)

		sum := big.NewInt(0)
		for i := 256; i >= 0; i-- {
			sum.Mul(sum, big.NewInt(2))
			if sNaf[i] == 0 {

			} else if sNaf[i] > 0 {
				index := sNaf[i] / 2
				sum.Add(sum, big.NewInt(int64(2*index+1)))
				count++
			} else {
				index := -sNaf[i] / 2
				sum.Sub(sum, big.NewInt(int64(2*index+1)))
				count++
			}

		}

		result := new(big.Int).SetBytes(data)
		if result.Cmp(sum) != 0 {
			fmt.Println(result.Text(10))
			fmt.Println(sum.Text(10))
			fmt.Println("------------------------------")
			fmt.Println(new(big.Int).Sub(result, sum).Text(16))
		}

	}
	fmt.Println(float64(count) / float64(1000000))
}
