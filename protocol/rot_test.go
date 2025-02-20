package protocol

//func TestRot(t *testing.T) {
//	vector := []int32{0, 1, 2, 3, 4, 5}
//	rotV := Rot(vector)
//	PrintMatrix(rotV)
//	fmt.Println("----------------------------------------------------")
//	vectorB := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}
//	rotVB := RotBn(vectorB)
//	PrintMatrixBn(rotVB)
//	fmt.Println("----------------------------------------------------")
//	rotVT := TransMatrix(rotV)
//	PrintMatrix(rotVT)
//	fmt.Println("----------------------------------------------------")
//	rotVTB := TransMatrix(rotVT)
//	PrintMatrix(rotVTB)
//}
//
//func TestRotVector(t *testing.T) {
//	vectorP0 := []int32{0, 1, 2, 3}
//	vectorP1 := []int32{100, 110, 120, 130}
//	vectorDelta := []int32{8, 0, 0, 0}
//	vector0 := make([]int32, 4)
//	vector1 := []int32{1, 0, 0, 0}
//	m := make([][][]int32, 2)
//	m[0] = [][]int32{vectorP0, vector0, vectorDelta}
//	m[1] = [][]int32{vectorP1, vector1, vector0}
//
//	M := RotVector(m)
//	PrintMatrix(M)
//	fmt.Println("------------------------------------------------------")
//	TM := TransMatrix(M)
//	PrintMatrix(TM)
//	fmt.Println("------------------------------------------------------")
//
//}
//
//func TestMul(t *testing.T) {
//	vectorP0 := []int32{0, 1, 2, 3}
//	v0 := Rot(vectorP0)
//	PrintMatrix(v0)
//	fmt.Println("------------------------------------")
//	vectorP1 := []int32{100, 110, 120, 130}
//
//	v1 := Rot(vectorP1)
//	PrintMatrix(v1)
//	fmt.Println("------------------------------------")
//	v2 := MatrixMul(v0, v1)
//	PrintMatrix(v2)
//	fmt.Println("------------------------------------")
//	PrintMatrix(v2)
//}
