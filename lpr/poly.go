package lpr

func PolyMul(a, b []int32, q int32) []int32 {
	num := len(a)
	product := make([]int64, num*2)
	for i := 0; i < num; i++ {
		for j := 0; j < num; j++ {
			product[i+j] += int64(a[i]) * int64(b[j])
		}
	}
	result := make([]int32, num)
	for i := 0; i < num; i++ {
		product[i] -= product[i+num]
		tmp := product[i] % int64(q)
		if tmp >= int64(q)/2 {
			tmp -= int64(q)
		} else if tmp < -int64(q)/2 {
			tmp += int64(q)
		}
		result[i] = int32(tmp)
	}
	return result
}

func PolyScalar(a []int32, delta int32, q int32) []int32 {
	num := len(a)
	result := make([]int32, num)
	for i := 0; i < num; i++ {
		tmp := int64(a[i]) * int64(delta)
		tmp = tmp % int64(q)
		if tmp >= int64(q/2) {
			tmp -= int64(q)
		} else if tmp < -int64(q)/2 {
			tmp += int64(q)
		}
		result[i] = int32(tmp)
	}
	return result
}

func PolyAdd(a, b []int32, q int32) []int32 {
	num := len(a)
	result := make([]int32, num)
	for i := 0; i < num; i++ {
		tmp := int64(a[i]) + int64(b[i])
		tmp = tmp % int64(q)
		if tmp >= int64(q/2) {
			tmp -= int64(q)
		} else if tmp < -int64(q)/2 {
			tmp += int64(q)
		}
		result[i] = int32(tmp)
	}
	return result
}

func PolyNeg(a []int32, q int32) []int32 {
	num := len(a)
	result := make([]int32, num)
	for i := 0; i < num; i++ {
		if a[i] == -q/2 {
			result[i] = a[i]
		} else {
			result[i] = -a[i]
		}
	}
	return result
}
