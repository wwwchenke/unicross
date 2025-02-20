package protocol

type MatrixA struct {
	P0    []int32
	P1    []int32
	Delta int32
}

type VectorS struct {
	U  []int32
	E1 []int32
	E2 []int32
	M  []int32
}

type VectorT struct {
	T0 []int32
	T1 []int32
}

type VectorAS struct {
	AS0 []int32
	AS1 []int32
}

type VectorProve struct {
	RLeft  []int32
	RRight []int32
}
