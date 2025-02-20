package protocol

import "fmt"

func PolyAdd(u []int32, v []int32) []int32 {
	maxLength := len(u)
	minLength := len(u)
	m := u
	if len(v) > maxLength {
		maxLength = len(v)
		m = v
	}
	if len(v) < minLength {
		minLength = len(v)
	}
	res := make([]int32, maxLength)
	for i := 0; i < minLength; i++ {
		res[i] = u[i] + v[i]
	}
	for i := minLength; i < maxLength; i++ {
		res[i] = m[i]
	}
	return res
}

func PolySub(u []int32, v []int32) []int32 {
	maxLength := len(u)
	minLength := len(u)
	if len(v) > maxLength {
		maxLength = len(v)
	}
	if len(v) < minLength {
		minLength = len(v)
	}
	res := make([]int32, maxLength)
	for i := 0; i < minLength; i++ {
		res[i] = u[i] - v[i]
	}
	if len(u) > len(v) {
		for i := minLength; i < maxLength; i++ {
			res[i] = u[i]
		}
	} else {
		for i := minLength; i < maxLength; i++ {
			res[i] = -v[i]
		}
	}
	return res
}

func PolyMul(u []int32, v []int32) []int32 {
	res := make([]int32, len(u)+len(v)-1)
	for i := 0; i < len(u); i++ {
		for j := 0; j < len(v); j++ {
			res[i+j] += u[i] * v[j]
		}
	}
	return res
}

func PolyScalar(u int32, v []int32) []int32 {
	res := make([]int32, len(v))
	for i := 0; i < len(res); i++ {
		res[i] = v[i] * u
	}
	return res
}

// PolyDiv breaks u after calculation
func PolyDiv(u []int32, v []int32) ([]int32, error) {
	m := len(u)
	n := len(v)
	if m < n {
		return nil, fmt.Errorf("Poly div length error\n")
	}
	k := m - n + 1
	res := make([]int32, k)
	ll := m - 1
	mm := 0
	for i := k; i > 0; i-- {
		res[i-1] = u[ll] / v[n-1]
		mm = ll
		for j := 1; j < n; j++ {
			u[mm-1] -= res[i-1] * v[n-j-1]
			mm -= 1
		}
		ll -= 1
	}
	return res, nil
}

func PolyExactDiv(u []int32, v int32) ([]int32, error) {
	res := make([]int32, len(u))
	for i := 0; i < len(u); i++ {
		res[i] = u[i] / v
		if res[i]*v != u[i] {
			return nil, fmt.Errorf("Division not exact\n")
		}
	}
	return res, nil
}

func PolyMod(res []int32, q int32) {
	for i := 0; i < len(res); i++ {
		res[i] = res[i] % q
		if res[i] >= q/2 {
			res[i] -= q
		} else if res[i] < -q/2 {
			res[i] += q
		}
	}
}
