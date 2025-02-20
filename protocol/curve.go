package protocol

import "volley/curve"

var fastCurve curve.FastCurve

func SetCurve(c curve.FastCurve) {
	fastCurve = c
}
