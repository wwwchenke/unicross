package lpr

import (
	"encoding/binary"
	"os"
)

func ReplaceRandomBy(d int32, fileName string) []int32 {
	dataBytes, err := os.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	if len(dataBytes) != 4*int(d) {
		panic("Data length error")
	}
	result := make([]int32, d)
	for i := 0; i < int(d); i++ {
		u := binary.LittleEndian.Uint32(dataBytes[i*4 : i*4+4])
		result[i] = int32(u)
	}
	return result
}
