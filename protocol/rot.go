package protocol

import (
	"fmt"
	"math/big"
	vc "volley/curve"
)

func Rot(vector []int32) [][]int32 {
	d := len(vector)
	res := make([][]int32, d)
	for i := 0; i < d; i++ {
		res[i] = make([]int32, d)
		for j := 0; j < d; j++ {
			res[i][j] = vector[(i+d-j)%d]
		}
		for j := i + 1; j < d; j++ {
			res[i][j] = -res[i][j]
		}
	}
	return res
}

func RotBn(vector []*big.Int) [][]*big.Int {
	d := len(vector)
	res := make([][]*big.Int, d)
	for i := 0; i < d; i++ {
		res[i] = make([]*big.Int, d)
		for j := 0; j < d; j++ {
			res[i][j] = new(big.Int).Set(vector[(i+d-j)%d])
		}
		for j := i + 1; j < d; j++ {
			res[i][j].Neg(res[i][j])
		}
	}
	return res
}

func RotVector(matrix [][][]int32) [][]int32 {
	d := len(matrix[0][0])
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {
			element := matrix[i][j]
			if len(element) != d {
				panic("matrix error")
			}
		}
	}

	res := make([][]int32, len(matrix)*d)
	for i := 0; i < len(matrix)*d; i++ {
		res[i] = make([]int32, len(matrix[0])*d)
	}
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[0]); j++ {
			tmp := Rot(matrix[i][j])
			for m := 0; m < d; m++ {
				for n := 0; n < d; n++ {
					res[i*d+m][j*d+n] = tmp[m][n]
				}
			}
		}
	}
	return res
}

func RotVectorBn(matrix [][][]*big.Int) [][]*big.Int {
	d := len(matrix[0][0])
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {
			element := matrix[i][j]
			if len(element) != d {
				panic("matrix error")
			}
		}
	}

	res := make([][]*big.Int, len(matrix)*d)
	for i := 0; i < len(matrix)*d; i++ {
		res[i] = make([]*big.Int, len(matrix[0])*d)
	}
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[0]); j++ {
			tmp := RotBn(matrix[i][j])
			for m := 0; m < d; m++ {
				for n := 0; n < d; n++ {
					res[i*d+m][j*d+n] = new(big.Int).Set(tmp[m][n])
				}
			}
		}
	}
	return res
}

func PrintMatrix(matrix [][]int32) {
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {
			fmt.Printf("%8d", matrix[i][j])
		}
		fmt.Println()
	}
}

func PrintMatrixBn(matrix [][]*big.Int) {
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {
			txt := matrix[i][j].Text(10)
			for k := 0; k < 8-len(txt); k++ {
				fmt.Printf(" ")
			}
			fmt.Print(txt)
		}
		fmt.Println()
	}
}

func TransMatrix(matrix [][]int32) [][]int32 {
	r := len(matrix)
	c := len(matrix[0])
	res := make([][]int32, c)
	for i := 0; i < c; i++ {
		res[i] = make([]int32, r)
		for j := 0; j < r; j++ {
			res[i][j] = matrix[j][i]
		}
	}
	return res
}

func TransMatrixBn(matrix [][]*big.Int) [][]*big.Int {
	r := len(matrix)
	c := len(matrix[0])
	res := make([][]*big.Int, c)
	for i := 0; i < c; i++ {
		res[i] = make([]*big.Int, r)
		for j := 0; j < r; j++ {
			res[i][j] = new(big.Int).Set(matrix[j][i])
		}
	}
	return res
}

func Matrix(vector []int32) [][]int32 {
	res := make([][]int32, 1)
	res[0] = vector
	return res
}

func MatrixBn(vector []*big.Int) [][]*big.Int {
	res := make([][]*big.Int, 1)
	res[0] = vector
	return res
}

func MakeVector(a int32, d int) []int32 {
	res := make([]int32, d)
	res[0] = a
	return res
}

func MakeVectorBn(a *big.Int, d int) []*big.Int {
	res := make([]*big.Int, d)
	res[0] = new(big.Int).Set(a)
	for i := 1; i < d; i++ {
		res[i] = big.NewInt(0)
	}
	return res
}

func MakeVector2(b int32) []int32 {
	res := make([]int32, b)
	res[0] = 1
	for i := int32(1); i < b; i++ {
		res[i] = res[i-1] * 2
	}
	res[b-1] *= -1
	return res
}

func Kronecker(a []int32, b []int32) []int32 {
	res := make([]int32, len(a)*len(b))
	count := 0
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			res[count] = a[i] * b[j]
			count++
		}
	}
	return res
}

func KroneckerBn(a []*big.Int, b []*big.Int, q *big.Int) []*big.Int {
	res := make([]*big.Int, len(a)*len(b))
	count := 0
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			res[count] = new(big.Int).Mul(a[i], b[j])
			res[count].Mod(res[count], q)
			count++
		}
	}
	return res
}

func ToBn(a []int32) []*big.Int {
	res := make([]*big.Int, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = big.NewInt(int64(a[i]))
	}
	return res
}

func MatrixMul(a [][]int32, b [][]int32) [][]int32 {
	res := make([][]int32, len(a))
	for i := 0; i < len(res); i++ {
		if len(a[i]) != len(b) {
			panic("mul error")
		}
		res[i] = make([]int32, len(b[0]))
		for j := 0; j < len(b[0]); j++ {
			for k := 0; k < len(b); k++ {
				res[i][j] += a[i][k] * b[k][j]
			}
		}
	}
	return res
}

func MatrixMulBn(a [][]*big.Int, b [][]*big.Int, q *big.Int) [][]*big.Int {
	res := make([][]*big.Int, len(a))
	for i := 0; i < len(res); i++ {
		if len(a[i]) != len(b) {
			panic("mul error")
		}
		res[i] = make([]*big.Int, len(b[0]))
		for j := 0; j < len(b[0]); j++ {
			res[i][j] = big.NewInt(0)
			for k := 0; k < len(b); k++ {
				tmp := new(big.Int).Mul(a[i][k], b[k][j])
				tmp.Mod(tmp, q)
				res[i][j].Add(res[i][j], tmp)
				res[i][j].Mod(res[i][j], q)
			}
		}
	}
	return res
}

func PrintEC(p vc.FastPoint, title string) {
	fmt.Printf("-------------%s-------------\n", title)
	x, y := p.Back()
	fmt.Println(x.Text(16))
	fmt.Println(y.Text(16))
}
