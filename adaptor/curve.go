package adaptor

import (
	"volley/curve"
)

var fastCurve curve.FastCurve
var bnLength int

func SetCurve(c curve.FastCurve) {
	fastCurve = c
	bitSize := c.Params().BitSize
	bnLength = (bitSize-1)/8 + 1

}
