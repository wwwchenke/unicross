// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copyright 2021 Viewsources team. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


// This part of codes are modified on basis of golang source codes about p256r1
// according to the feature of SM2 curve by viewsources team.
// 这部分码由观源科技团队在go标准库p256r1相关源码的基础上针对p256k1曲线的特点修改

// This file contains constant-time, 64-bit assembly implementation of
// SM2 Curve. The optimizations performed here are described in detail in:
// S.Gueron and V.Krasnov, "Fast prime field elliptic-curve cryptography with
//                          256-bit primes"
// https://eprint.iacr.org/2013/816.pdf


#include "textflag.h"

#define res_ptr DI
#define x_ptr SI
#define y_ptr CX

#define acc0 R8
#define acc1 R9
#define acc2 R10
#define acc3 R11
#define acc4 R12
#define acc5 R13
#define t0 R14
#define t1 R15

DATA p256k1p0<>+0x00(SB)/8, $0xfffffffefffffc2f
DATA p256k1p1<>+0x00(SB)/8, $0xffffffffffffffff
DATA p256k1p2<>+0x00(SB)/8, $0xffffffffffffffff
DATA p256k1p3<>+0x00(SB)/8, $0xffffffffffffffff
DATA p256k1pK0<>+0x00(SB)/8, $0xd838091dd2253531
DATA p256k1ordK0<>+0x00(SB)/8, $0x4b0dff665588b13f
DATA p256k1ord<>+0x00(SB)/8, $0xbfd25e8cd0364141
DATA p256k1ord<>+0x08(SB)/8, $0xbaaedce6af48a03b
DATA p256k1ord<>+0x10(SB)/8, $0xfffffffffffffffe
DATA p256k1ord<>+0x18(SB)/8, $0xffffffffffffffff
DATA p256k1one<>+0x00(SB)/8, $0x1000003d1
DATA p256k1one<>+0x08(SB)/8, $0x0
DATA p256k1one<>+0x10(SB)/8, $0x0
DATA p256k1one<>+0x18(SB)/8, $0x0
GLOBL p256k1p0<>(SB), 8, $8
GLOBL p256k1p1<>(SB), 8, $8
GLOBL p256k1p2<>(SB), 8, $8
GLOBL p256k1p3<>(SB), 8, $8
GLOBL p256k1pK0<>(SB), 8, $8
GLOBL p256k1ordK0<>(SB), 8, $8
GLOBL p256k1ord<>(SB), 8, $32
GLOBL p256k1one<>(SB), 8, $32

/* ---------------------------------------*/
// func p256k1LittleToBig(res []byte, in []uint64)
TEXT ·p256k1LittleToBig(SB),NOSPLIT,$0
	JMP ·p256k1BigToLittle(SB)
/* ---------------------------------------*/
// func p256k1BigToLittle(res []uint64, in []byte)
TEXT ·p256k1BigToLittle(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+24(FP), x_ptr

	MOVQ (8*0)(x_ptr), acc0
	MOVQ (8*1)(x_ptr), acc1
	MOVQ (8*2)(x_ptr), acc2
	MOVQ (8*3)(x_ptr), acc3

	BSWAPQ acc0
	BSWAPQ acc1
	BSWAPQ acc2
	BSWAPQ acc3

	MOVQ acc3, (8*0)(res_ptr)
	MOVQ acc2, (8*1)(res_ptr)
	MOVQ acc1, (8*2)(res_ptr)
	MOVQ acc0, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// func p256k1Neg(val []uint64)
TEXT ·p256k1Neg(SB),NOSPLIT,$0
	MOVQ val+0(FP), res_ptr
	MOVQ cond+24(FP), t0
	// acc = poly
	MOVQ p256k1p0<>(SB), acc0
	MOVQ p256k1p1<>(SB), acc1
	MOVQ p256k1p2<>(SB), acc2
	MOVQ p256k1p3<>(SB), acc3
	// Load the original value
	MOVQ (8*0)(res_ptr), acc5
	MOVQ (8*1)(res_ptr), x_ptr
	MOVQ (8*2)(res_ptr), y_ptr
	MOVQ (8*3)(res_ptr), t1
	// Speculatively subtract
	SUBQ acc5, acc0
	SBBQ x_ptr, acc1
	SBBQ y_ptr, acc2
	SBBQ t1, acc3
	// Store result
	MOVQ acc0, (8*0)(res_ptr)
	MOVQ acc1, (8*1)(res_ptr)
	MOVQ acc2, (8*2)(res_ptr)
	MOVQ acc3, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// func p256k1Sqr(res, in []uint64, n int)
TEXT ·p256k1Sqr(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+24(FP), x_ptr
	MOVQ n+48(FP), BX

sqrLoop:

	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc1
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, acc5
	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, y_ptr
	XORQ t1, t1
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1
	// Missing products
	MOVQ (8*0)(x_ptr), AX
	MULQ AX
	MOVQ AX, acc0
	MOVQ DX, t0

	MOVQ (8*1)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc1
	ADCQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*2)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc3
	ADCQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*3)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc5
	ADCQ AX, y_ptr
	ADCQ DX, t1
	MOVQ t1, x_ptr
	// First reduction step
	MOVQ acc0, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB sqrrd1
    SUBQ $1, t1
    ADDQ AX, acc0
    ADCQ DX, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0, t1
sqrrd1:
    MOVQ t1, acc0
	// Second reduction step
	MOVQ acc1, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB sqrrd2
    SUBQ $1, t1
    ADDQ AX, acc1
    ADCQ DX, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ $0, t1
sqrrd2:
    MOVQ t1, acc1

	// Third reduction step
	MOVQ acc2, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB sqrrd3
    SUBQ $1, t1
    ADDQ AX, acc2
    ADCQ DX, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ $0xFFFFFFFFFFFFFFFF, acc1
    ADCQ $0, t1
sqrrd3:
    MOVQ t1, acc2

	// Last reduction step
	XORQ t0, t0
	MOVQ acc3, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB sqrrd4
    SUBQ $1, t1
    ADDQ AX, acc3
    ADCQ DX, acc0
    ADCQ $0xFFFFFFFFFFFFFFFF, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0, t1
sqrrd4:
    MOVQ t1, acc3

	// Add bits [511:256] of the sqr result
	ADCQ acc4, acc0
	ADCQ acc5, acc1
	ADCQ y_ptr, acc2
	ADCQ x_ptr, acc3
	ADCQ $0, t0

	MOVQ acc0, acc4
	MOVQ acc1, acc5
	MOVQ acc2, y_ptr
	MOVQ acc3, t1
	// Subtract p256
	SUBQ p256k1p0<>(SB), acc0
	SBBQ p256k1p1<>(SB) ,acc1
	SBBQ p256k1p2<>(SB), acc2
	SBBQ p256k1p3<>(SB), acc3
	SBBQ $0, t0

	CMOVQCS acc4, acc0
	CMOVQCS acc5, acc1
	CMOVQCS y_ptr, acc2
	CMOVQCS t1, acc3

	MOVQ acc0, (8*0)(res_ptr)
	MOVQ acc1, (8*1)(res_ptr)
	MOVQ acc2, (8*2)(res_ptr)
	MOVQ acc3, (8*3)(res_ptr)
	MOVQ res_ptr, x_ptr
	DECQ BX
	JNE  sqrLoop

	RET
/* ---------------------------------------*/
// func p256k1Mul(res, in1, in2 []uint64)
TEXT ·p256k1Mul(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in1+24(FP), x_ptr
	MOVQ in2+48(FP), y_ptr
	// x * y[0]
	MOVQ (8*0)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc0
	MOVQ DX, acc1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	XORQ acc5, acc5
	// First reduction step
	MOVQ acc0, AX
	MULQ p256k1pK0<>(SB)
	MOVQ AX, t1
	MULQ p256k1p0<>(SB)
	SUBQ t1, DX
	JNB mulrd1
    SUBQ $1, t1
    ADDQ AX, acc0
    ADCQ DX, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ t1, acc4
    ADCQ $0, acc5
mulrd1:
	XORQ acc0, acc0
	// x * y[1]
	MOVQ (8*1)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5
	ADCQ $0, acc0
	// Second reduction step
	MOVQ acc1, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB mulrd2
    SUBQ $1, t1
    ADDQ AX, acc1
    ADCQ DX, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc4
    ADCQ t1, acc5
    ADCQ $0, acc0
mulrd2:
    XORQ acc1, acc1
	// x * y[2]
	MOVQ (8*2)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ DX, acc0
	ADCQ $0, acc1
	// Third reduction step
	MOVQ acc2, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)

    SUBQ t1, DX
    JNB mulrd3
    SUBQ $1, t1
    ADDQ AX, acc2
    ADCQ DX, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc4
    ADCQ $0xFFFFFFFFFFFFFFFF, acc5
    ADCQ t1, acc0
    ADCQ $0, acc1
mulrd3:
    XORQ acc2, acc2

	// x * y[3]
	MOVQ (8*3)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	// Last reduction step
	MOVQ acc3, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB mulrd4
    SUBQ $1, t1
    ADDQ AX, acc3
    ADCQ DX, acc4
    ADCQ $0xFFFFFFFFFFFFFFFF, acc5
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ t1, acc1
    ADCQ $0, acc2
mulrd4:
	// Copy result [255:0]
	MOVQ acc4, x_ptr
	MOVQ acc5, acc3
	MOVQ acc0, t0
	MOVQ acc1, t1
	// Subtract p256
	SUBQ p256k1p0<>(SB), acc4
	SBBQ p256k1p1<>(SB) ,acc5
	SBBQ p256k1p2<>(SB), acc0
	SBBQ p256k1p3<>(SB), acc1
	SBBQ $0, acc2

	CMOVQCS x_ptr, acc4
	CMOVQCS acc3, acc5
	CMOVQCS t0, acc0
	CMOVQCS t1, acc1

	MOVQ acc4, (8*0)(res_ptr)
	MOVQ acc5, (8*1)(res_ptr)
	MOVQ acc0, (8*2)(res_ptr)
	MOVQ acc1, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// func p256k1FromMont(res, in []uint64)
TEXT ·p256k1FromMont(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+24(FP), x_ptr

	MOVQ (8*0)(x_ptr), acc0
	MOVQ (8*1)(x_ptr), acc1
	MOVQ (8*2)(x_ptr), acc2
	MOVQ (8*3)(x_ptr), acc3
	XORQ acc4, acc4

	// Only reduce, no multiplications are needed
	// First stage
	MOVQ acc0, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB fmrd1
    SUBQ $1, t1
    ADDQ AX, acc0
    ADCQ DX, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ t1, acc4
fmrd1:
    XORQ acc5, acc5
	// Second stage
	MOVQ acc1, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB fmrd2
    SUBQ $1, t1
    ADDQ AX, acc1
    ADCQ DX, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc4
    ADCQ t1, acc5
fmrd2:
    XORQ acc0, acc0
	// Third stage
	MOVQ acc2, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB fmrd3
    SUBQ $1, t1
    ADDQ AX, acc2
    ADCQ DX, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc4
    ADCQ $0xFFFFFFFFFFFFFFFF, acc5
    ADCQ t1, acc0
fmrd3:
    XORQ acc1, acc1
	// Last stage
	MOVQ acc3, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, t1
    MULQ p256k1p0<>(SB)
    SUBQ t1, DX
    JNB fmrd4
    SUBQ $1, t1
    ADDQ AX, acc3
    ADCQ DX, acc4
    ADCQ $0xFFFFFFFFFFFFFFFF, acc5
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ t1, acc1
fmrd4:

	MOVQ acc4, x_ptr
	MOVQ acc5, acc3
	MOVQ acc0, t0
	MOVQ acc1, t1

	SUBQ p256k1p0<>(SB), acc4
	SBBQ p256k1p1<>(SB), acc5
	SBBQ p256k1p2<>(SB), acc0
	SBBQ p256k1p3<>(SB), acc1

	CMOVQCS x_ptr, acc4
	CMOVQCS acc3, acc5
	CMOVQCS t0, acc0
	CMOVQCS t1, acc1

	MOVQ acc4, (8*0)(res_ptr)
	MOVQ acc5, (8*1)(res_ptr)
	MOVQ acc0, (8*2)(res_ptr)
	MOVQ acc1, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// func p256k1OrdMul(res, in1, in2 []uint64)
TEXT ·p256k1OrdMul(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in1+24(FP), x_ptr
	MOVQ in2+48(FP), y_ptr
	// x * y[0]
	MOVQ (8*0)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc0
	MOVQ DX, acc1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	XORQ acc5, acc5
	// First reduction step
	MOVQ acc0, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ DX, acc4
	ADCQ $0, acc5
	// x * y[1]
	MOVQ (8*1)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5
	ADCQ $0, acc0
	// Second reduction step
	MOVQ acc1, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ DX, acc5
	ADCQ $0, acc0
	// x * y[2]
	MOVQ (8*2)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ DX, acc0
	ADCQ $0, acc1
	// Third reduction step
	MOVQ acc2, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ DX, acc0
	ADCQ $0, acc1
	// x * y[3]
	MOVQ (8*3)(y_ptr), t0

	MOVQ (8*0)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	// Last reduction step
	MOVQ acc3, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x10(SB), AX
	MULQ t0
	ADDQ t1, acc5
	ADCQ $0, DX
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x18(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ DX, acc1
	ADCQ $0, acc2
	// Copy result [255:0]
	MOVQ acc4, x_ptr
	MOVQ acc5, acc3
	MOVQ acc0, t0
	MOVQ acc1, t1
	// Subtract p256
	SUBQ p256k1ord<>+0x00(SB), acc4
	SBBQ p256k1ord<>+0x08(SB) ,acc5
	SBBQ p256k1ord<>+0x10(SB), acc0
	SBBQ p256k1ord<>+0x18(SB), acc1
	SBBQ $0, acc2

	CMOVQCS x_ptr, acc4
	CMOVQCS acc3, acc5
	CMOVQCS t0, acc0
	CMOVQCS t1, acc1

	MOVQ acc4, (8*0)(res_ptr)
	MOVQ acc5, (8*1)(res_ptr)
	MOVQ acc0, (8*2)(res_ptr)
	MOVQ acc1, (8*3)(res_ptr)

	RET
/* ---------------------------------------*/
// func p256k1OrdSqr(res, in []uint64, n int)
TEXT ·p256k1OrdSqr(SB),NOSPLIT,$0
	MOVQ res+0(FP), res_ptr
	MOVQ in+24(FP), x_ptr
	MOVQ n+48(FP), BX

ordSqrLoop:

	// y[1:] * y[0]
	MOVQ (8*0)(x_ptr), t0

	MOVQ (8*1)(x_ptr), AX
	MULQ t0
	MOVQ AX, acc1
	MOVQ DX, acc2

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, acc3

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, acc4
	// y[2:] * y[1]
	MOVQ (8*1)(x_ptr), t0

	MOVQ (8*2)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ t1, acc4
	ADCQ $0, DX
	ADDQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, acc5
	// y[3] * y[2]
	MOVQ (8*2)(x_ptr), t0

	MOVQ (8*3)(x_ptr), AX
	MULQ t0
	ADDQ AX, acc5
	ADCQ $0, DX
	MOVQ DX, y_ptr
	XORQ t1, t1
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ acc4, acc4
	ADCQ acc5, acc5
	ADCQ y_ptr, y_ptr
	ADCQ $0, t1
	// Missing products
	MOVQ (8*0)(x_ptr), AX
	MULQ AX
	MOVQ AX, acc0
	MOVQ DX, t0

	MOVQ (8*1)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc1
	ADCQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*2)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc3
	ADCQ AX, acc4
	ADCQ $0, DX
	MOVQ DX, t0

	MOVQ (8*3)(x_ptr), AX
	MULQ AX
	ADDQ t0, acc5
	ADCQ AX, y_ptr
	ADCQ DX, t1
	MOVQ t1, x_ptr
	// First reduction step
	MOVQ acc0, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc1
	ADCQ $0, DX
	ADDQ AX, acc1

	MOVQ t0, acc0
	ADCQ DX, acc2
	ADCQ $0, acc3
	ADCQ $0, acc0
	SUBQ t0, acc2
	SBBQ $0, acc3
	SBBQ $0, acc0
	SUBQ t0, acc2
	SBBQ $0, acc3
	SBBQ $0, acc0
	// Second reduction step
	MOVQ acc1, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc1
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc2
	ADCQ $0, DX
	ADDQ AX, acc2

    MOVQ t0, acc1
    ADCQ DX, acc3
    ADCQ $0, acc0
    ADCQ $0, acc1
    SUBQ t0, acc3
    SBBQ $0, acc0
    SBBQ $0, acc1
    SUBQ t0, acc3
    SBBQ $0, acc0
    SBBQ $0, acc1

	// Third reduction step
	MOVQ acc2, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc2
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc3
	ADCQ $0, DX
	ADDQ AX, acc3

    MOVQ t0, acc2
    ADCQ DX, acc0
    ADCQ $0, acc1
    ADCQ $0, acc2
    SUBQ t0, acc0
    SBBQ $0, acc1
    SBBQ $0, acc2
    SUBQ t0, acc0
    SBBQ $0, acc1
    SBBQ $0, acc2

	// Last reduction step
	MOVQ acc3, AX
	MULQ p256k1ordK0<>(SB)
	MOVQ AX, t0

	MOVQ p256k1ord<>+0x00(SB), AX
	MULQ t0
	ADDQ AX, acc3
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ p256k1ord<>+0x08(SB), AX
	MULQ t0
	ADDQ t1, acc0
	ADCQ $0, DX
	ADDQ AX, acc0
	ADCQ $0, DX
	MOVQ DX, t1

	MOVQ t0, acc3
    ADCQ DX, acc1
    ADCQ $0, acc2
    ADCQ $0, acc3
    SUBQ t0, acc1
    SBBQ $0, acc2
    SBBQ $0, acc3
    SUBQ t0, acc1
    SBBQ $0, acc2
    SBBQ $0, acc3

	XORQ t0, t0
	// Add bits [511:256] of the sqr result
	ADCQ acc4, acc0
	ADCQ acc5, acc1
	ADCQ y_ptr, acc2
	ADCQ x_ptr, acc3
	ADCQ $0, t0

	MOVQ acc0, acc4
	MOVQ acc1, acc5
	MOVQ acc2, y_ptr
	MOVQ acc3, t1
	// Subtract p256
	SUBQ p256k1ord<>+0x00(SB), acc0
	SBBQ p256k1ord<>+0x08(SB) ,acc1
	SBBQ p256k1ord<>+0x10(SB), acc2
	SBBQ p256k1ord<>+0x18(SB), acc3
	SBBQ $0, t0

	CMOVQCS acc4, acc0
	CMOVQCS acc5, acc1
	CMOVQCS y_ptr, acc2
	CMOVQCS t1, acc3

	MOVQ acc0, (8*0)(res_ptr)
	MOVQ acc1, (8*1)(res_ptr)
	MOVQ acc2, (8*2)(res_ptr)
	MOVQ acc3, (8*3)(res_ptr)
	MOVQ res_ptr, x_ptr
	DECQ BX
	JNE ordSqrLoop

	RET
/* ---------------------------------------*/
#undef res_ptr
#undef x_ptr
#undef y_ptr

#undef acc0
#undef acc1
#undef acc2
#undef acc3
#undef acc4
#undef acc5
#undef t0
#undef t1
/* ---------------------------------------*/
#define mul0 AX
#define mul1 DX
#define acc0 BX
#define acc1 CX
#define acc2 R8
#define acc3 R9
#define acc4 R10
#define acc5 R11
#define acc6 R12
#define acc7 R13
#define t0 R14
#define t1 R15
#define t2 DI
#define t3 SI
#define hlp BP
/* ---------------------------------------*/
TEXT p256k1SubInternal(SB),NOSPLIT,$0
	XORQ mul0, mul0
	SUBQ t0, acc4
	SBBQ t1, acc5
	SBBQ t2, acc6
	SBBQ t3, acc7
	SBBQ $0, mul0

	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3

	ADDQ p256k1p0<>(SB), acc4
	ADCQ p256k1p1<>(SB), acc5
	ADCQ p256k1p2<>(SB), acc6
	ADCQ p256k1p3<>(SB), acc7
	ANDQ $1, mul0

	CMOVQEQ acc0, acc4
	CMOVQEQ acc1, acc5
	CMOVQEQ acc2, acc6
	CMOVQEQ acc3, acc7

	RET
/* ---------------------------------------*/
TEXT p256k1MulInternal(SB),NOSPLIT,$8
	MOVQ acc4, mul0
	MULQ t0
	MOVQ mul0, acc0
	MOVQ mul1, acc1

	MOVQ acc4, mul0
	MULQ t1
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, acc2

	MOVQ acc4, mul0
	MULQ t2
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc3

	MOVQ acc4, mul0
	MULQ t3
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, acc4

	MOVQ acc5, mul0
	MULQ t0
	ADDQ mul0, acc1
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t1
	ADDQ hlp, acc2
	ADCQ $0, mul1
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t2
	ADDQ hlp, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ t3
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, acc5

	MOVQ acc6, mul0
	MULQ t0
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t1
	ADDQ hlp, acc3
	ADCQ $0, mul1
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t2
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc6, mul0
	MULQ t3
	ADDQ hlp, acc5
	ADCQ $0, mul1
	ADDQ mul0, acc5
	ADCQ $0, mul1
	MOVQ mul1, acc6

	MOVQ acc7, mul0
	MULQ t0
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t1
	ADDQ hlp, acc4
	ADCQ $0, mul1
	ADDQ mul0, acc4
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t2
	ADDQ hlp, acc5
	ADCQ $0, mul1
	ADDQ mul0, acc5
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc7, mul0
	MULQ t3
	ADDQ hlp, acc6
	ADCQ $0, mul1
	ADDQ mul0, acc6
	ADCQ $0, mul1
	MOVQ mul1, acc7
	// First reduction step
	MOVQ acc0, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB mulinrd1
    SUBQ $1, hlp
    ADDQ AX, acc0
    ADCQ DX, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0, hlp
mulinrd1:
    MOVQ hlp, acc0

	// Second reduction step
	MOVQ acc1, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB mulinrd2
    SUBQ $1, hlp
    ADDQ AX, acc1
    ADCQ DX, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ $0, hlp
mulinrd2:
    MOVQ hlp, acc1

	// Third reduction step
	MOVQ acc2, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB mulinrd3
    SUBQ $1, hlp
    ADDQ AX, acc2
    ADCQ DX, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ $0xFFFFFFFFFFFFFFFF, acc1
    ADCQ $0, hlp
mulinrd3:
    MOVQ hlp, acc2

	// Last reduction step
	MOVQ acc3, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB mulinrd4
    SUBQ $1, hlp
    ADDQ AX, acc3
    ADCQ DX, acc0
    ADCQ $0xFFFFFFFFFFFFFFFF, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0, hlp
mulinrd4:
    MOVQ hlp, acc3
	MOVQ $0, BP
	// Add bits [511:256] of the result
	ADCQ acc0, acc4
	ADCQ acc1, acc5
	ADCQ acc2, acc6
	ADCQ acc3, acc7
	ADCQ $0, hlp
	// Copy result
	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3
	// Subtract p256
	SUBQ p256k1p0<>(SB), acc4
	SBBQ p256k1p1<>(SB) ,acc5
	SBBQ p256k1p2<>(SB), acc6
	SBBQ p256k1p3<>(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS acc0, acc4
	CMOVQCS acc1, acc5
	CMOVQCS acc2, acc6
	CMOVQCS acc3, acc7

	RET
/* ---------------------------------------*/
TEXT p256k1SqrInternal(SB),NOSPLIT,$8

	MOVQ acc4, mul0
	MULQ acc5
	MOVQ mul0, acc1
	MOVQ mul1, acc2

	MOVQ acc4, mul0
	MULQ acc6
	ADDQ mul0, acc2
	ADCQ $0, mul1
	MOVQ mul1, acc3

	MOVQ acc4, mul0
	MULQ acc7
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, t0

	MOVQ acc5, mul0
	MULQ acc6
	ADDQ mul0, acc3
	ADCQ $0, mul1
	MOVQ mul1, hlp

	MOVQ acc5, mul0
	MULQ acc7
	ADDQ hlp, t0
	ADCQ $0, mul1
	ADDQ mul0, t0
	ADCQ $0, mul1
	MOVQ mul1, t1

	MOVQ acc6, mul0
	MULQ acc7
	ADDQ mul0, t1
	ADCQ $0, mul1
	MOVQ mul1, t2
	XORQ t3, t3
	// *2
	ADDQ acc1, acc1
	ADCQ acc2, acc2
	ADCQ acc3, acc3
	ADCQ t0, t0
	ADCQ t1, t1
	ADCQ t2, t2
	ADCQ $0, t3
	// Missing products
	MOVQ acc4, mul0
	MULQ mul0
	MOVQ mul0, acc0
	MOVQ DX, acc4

	MOVQ acc5, mul0
	MULQ mul0
	ADDQ acc4, acc1
	ADCQ mul0, acc2
	ADCQ $0, DX
	MOVQ DX, acc4

	MOVQ acc6, mul0
	MULQ mul0
	ADDQ acc4, acc3
	ADCQ mul0, t0
	ADCQ $0, DX
	MOVQ DX, acc4

	MOVQ acc7, mul0
	MULQ mul0
	ADDQ acc4, t1
	ADCQ mul0, t2
	ADCQ DX, t3
    // First reduction step
	MOVQ acc0, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB sqrinrd1
    SUBQ $1, hlp
    ADDQ AX, acc0
    ADCQ DX, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0, hlp
sqrinrd1:
    MOVQ hlp, acc0
	// Second reduction step
	MOVQ acc1, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB sqrinrd2
    SUBQ $1, hlp
    ADDQ AX, acc1
    ADCQ DX, acc2
    ADCQ $0xFFFFFFFFFFFFFFFF, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ $0, hlp
sqrinrd2:
    MOVQ hlp, acc1
	// Third reduction step
	MOVQ acc2, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB sqrinrd3
    SUBQ $1, hlp
    ADDQ AX, acc2
    ADCQ DX, acc3
    ADCQ $0xFFFFFFFFFFFFFFFF, acc0
    ADCQ $0xFFFFFFFFFFFFFFFF, acc1
    ADCQ $0, hlp
sqrinrd3:
    MOVQ hlp, acc2
	// Last reduction step
	MOVQ acc3, AX
    MULQ p256k1pK0<>(SB)
    MOVQ AX, hlp
    MULQ p256k1p0<>(SB)
    SUBQ hlp, DX
    JNB sqrinrd4
    SUBQ $1, hlp
    ADDQ AX, acc3
    ADCQ DX, acc0
    ADCQ $0xFFFFFFFFFFFFFFFF, acc1
    ADCQ $0xFFFFFFFFFFFFFFFF, acc2
    ADCQ $0, hlp
sqrinrd4:
    MOVQ hlp, acc3
	MOVQ $0, BP
	// Add bits [511:256] of the result
	ADCQ acc0, t0
	ADCQ acc1, t1
	ADCQ acc2, t2
	ADCQ acc3, t3
	ADCQ $0, hlp
	// Copy result
	MOVQ t0, acc4
	MOVQ t1, acc5
	MOVQ t2, acc6
	MOVQ t3, acc7
	// Subtract p256
	SUBQ p256k1p0<>(SB), acc4
	SBBQ p256k1p1<>(SB) ,acc5
	SBBQ p256k1p2<>(SB), acc6
	SBBQ p256k1p3<>(SB), acc7
	SBBQ $0, hlp
	// If the result of the subtraction is negative, restore the previous result
	CMOVQCS t0, acc4
	CMOVQCS t1, acc5
	CMOVQCS t2, acc6
	CMOVQCS t3, acc7

	RET
/* ---------------------------------------*/
#define p256k1MulBy2Inline\
	XORQ mul0, mul0;\
	ADDQ acc4, acc4;\
	ADCQ acc5, acc5;\
	ADCQ acc6, acc6;\
	ADCQ acc7, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ p256k1p0<>(SB), t0;\
	SBBQ p256k1p1<>(SB), t1;\
	SBBQ p256k1p2<>(SB), t2;\
	SBBQ p256k1p3<>(SB), t3;\
	SBBQ $0, mul0;\
	CMOVQCS acc4, t0;\
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;
/* ---------------------------------------*/
#define p256k1AddInline \
	XORQ mul0, mul0;\
	ADDQ t0, acc4;\
	ADCQ t1, acc5;\
	ADCQ t2, acc6;\
	ADCQ t3, acc7;\
	ADCQ $0, mul0;\
	MOVQ acc4, t0;\
	MOVQ acc5, t1;\
	MOVQ acc6, t2;\
	MOVQ acc7, t3;\
	SUBQ p256k1p0<>(SB), t0;\
	SBBQ p256k1p1<>(SB), t1;\
	SBBQ p256k1p2<>(SB), t2;\
	SBBQ p256k1p3<>(SB), t3;\
	SBBQ $0, mul0;\
	CMOVQCS acc4, t0;\
	CMOVQCS acc5, t1;\
	CMOVQCS acc6, t2;\
	CMOVQCS acc7, t3;
/* ---------------------------------------*/
#define LDacc(src) MOVQ src(8*0), acc4; MOVQ src(8*1), acc5; MOVQ src(8*2), acc6; MOVQ src(8*3), acc7
#define LDt(src)   MOVQ src(8*0), t0; MOVQ src(8*1), t1; MOVQ src(8*2), t2; MOVQ src(8*3), t3
#define ST(dst)    MOVQ acc4, dst(8*0); MOVQ acc5, dst(8*1); MOVQ acc6, dst(8*2); MOVQ acc7, dst(8*3)
#define STt(dst)   MOVQ t0, dst(8*0); MOVQ t1, dst(8*1); MOVQ t2, dst(8*2); MOVQ t3, dst(8*3)
#define acc2t      MOVQ acc4, t0; MOVQ acc5, t1; MOVQ acc6, t2; MOVQ acc7, t3
#define t2acc      MOVQ t0, acc4; MOVQ t1, acc5; MOVQ t2, acc6; MOVQ t3, acc7
/* ---------------------------------------*/
#define x1in(off) (32*0 + off)(SP)
#define y1in(off) (32*1 + off)(SP)
#define z1in(off) (32*2 + off)(SP)
#define x2in(off) (32*3 + off)(SP)
#define y2in(off) (32*4 + off)(SP)
#define xout(off) (32*5 + off)(SP)
#define yout(off) (32*6 + off)(SP)
#define zout(off) (32*7 + off)(SP)
#define s2(off)   (32*8 + off)(SP)
#define z1sqr(off) (32*9 + off)(SP)
#define h(off)	  (32*10 + off)(SP)
#define r(off)	  (32*11 + off)(SP)
#define hsqr(off) (32*12 + off)(SP)
#define rsqr(off) (32*13 + off)(SP)
#define hcub(off) (32*14 + off)(SP)
#define rptr	  (32*15)(SP)
#define sel_save  (32*15 + 8)(SP)
#define zero_save (32*15 + 8 + 4)(SP)
/* ---------------------------------------*/
// func p256k1PointAddAffineAsm(res, in1, in2 []uint64, sign)
TEXT ·p256k1PointAddAffineAsm(SB),0,$512-96
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+24(FP), BX
	MOVQ in2+48(FP), CX
	MOVQ sign+72(FP), DX
	//MOVQ sel+80(FP), t1
	//MOVQ zero+88(FP), t2

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5

	MOVOU X0, x1in(16*0)
	MOVOU X1, x1in(16*1)
	MOVOU X2, y1in(16*0)
	MOVOU X3, y1in(16*1)
	MOVOU X4, z1in(16*0)
	MOVOU X5, z1in(16*1)

	MOVOU (16*0)(CX), X0
	MOVOU (16*1)(CX), X1

	MOVOU X0, x2in(16*0)
	MOVOU X1, x2in(16*1)
	// Store pointer to result
	MOVQ mul0, rptr
	//MOVL t1, sel_save
	//MOVL t2, zero_save
	// Negate y2in based on sign

	MOVQ (16*2 + 8*0)(CX), acc4
	MOVQ (16*2 + 8*1)(CX), acc5
	MOVQ (16*2 + 8*2)(CX), acc6
	MOVQ (16*2 + 8*3)(CX), acc7

	SUBQ $1, DX
    JB sel0

	MOVQ p256k1p0<>(SB), acc0
	MOVQ p256k1p1<>(SB), acc1
	MOVQ p256k1p2<>(SB), acc2
	MOVQ p256k1p3<>(SB), acc3
	XORQ mul0, mul0
	// Speculatively subtract
	SUBQ acc4, acc0
	SBBQ acc5, acc1
	SBBQ acc6, acc2
	SBBQ acc7, acc3
	SBBQ $0, mul0
	MOVQ acc0, t0
	MOVQ acc1, t1
	MOVQ acc2, t2
	MOVQ acc3, t3
	// Add in case the operand was > p256
	ADDQ p256k1p0<>(SB), acc0
	ADCQ p256k1p1<>(SB), acc1
	ADCQ p256k1p2<>(SB), acc2
	ADCQ p256k1p3<>(SB), acc3
	ADCQ $0, mul0
	CMOVQNE t0, acc0
	CMOVQNE t1, acc1
	CMOVQNE t2, acc2
	CMOVQNE t3, acc3
	JMP storey2in
	// If condition is 0, keep original value
	//TESTQ DX, DX
sel0:
	MOVQ acc4, acc0
	MOVQ acc5, acc1
	MOVQ acc6, acc2
	MOVQ acc7, acc3
	// Store result
storey2in:
	MOVQ acc0, y2in(8*0)
	MOVQ acc1, y2in(8*1)
	MOVQ acc2, y2in(8*2)
	MOVQ acc3, y2in(8*3)
	// Begin point add
	LDacc (z1in)
	CALL p256k1SqrInternal(SB)	// z1ˆ2
	ST (z1sqr)

	LDt (x2in)
	CALL p256k1MulInternal(SB)	// x2 * z1ˆ2

	LDt (x1in)
	CALL p256k1SubInternal(SB)	// h = u2 - u1
	ST (h)

	LDt (z1in)
	CALL p256k1MulInternal(SB)	// z3 = h * z1
	//ST (zout)
    MOVQ rptr, AX
    // Store z
    MOVQ acc4, (16*4 + 8*0)(AX)
    MOVQ acc5, (16*4 + 8*1)(AX)
    MOVQ acc6, (16*4 + 8*2)(AX)
    MOVQ acc7, (16*4 + 8*3)(AX)


	LDacc (z1sqr)
	CALL p256k1MulInternal(SB)	// z1ˆ3

	LDt (y2in)
	CALL p256k1MulInternal(SB)	// s2 = y2 * z1ˆ3
	ST (s2)

	LDt (y1in)
	CALL p256k1SubInternal(SB)	// r = s2 - s1
	ST (r)

	CALL p256k1SqrInternal(SB)	// rsqr = rˆ2
	ST (rsqr)

	LDacc (h)
	CALL p256k1SqrInternal(SB)	// hsqr = hˆ2
	ST (hsqr)

	LDt (h)
	CALL p256k1MulInternal(SB)	// hcub = hˆ3
	ST (hcub)

	LDt (y1in)
	CALL p256k1MulInternal(SB)	// y1 * hˆ3
	ST (s2)

	LDacc (x1in)
	LDt (hsqr)
	CALL p256k1MulInternal(SB)	// u1 * hˆ2
	ST (h)

	p256k1MulBy2Inline			// u1 * hˆ2 * 2, inline
	LDacc (rsqr)
	CALL p256k1SubInternal(SB)	// rˆ2 - u1 * hˆ2 * 2

	LDt (hcub)
	CALL p256k1SubInternal(SB)
	//ST (xout)
    MOVQ rptr, AX
    // Store x
    MOVQ acc4, (16*0 + 8*0)(AX)
    MOVQ acc5, (16*0 + 8*1)(AX)
    MOVQ acc6, (16*0 + 8*2)(AX)
    MOVQ acc7, (16*0 + 8*3)(AX)

	MOVQ acc4, t0
	MOVQ acc5, t1
	MOVQ acc6, t2
	MOVQ acc7, t3
	LDacc (h)
	CALL p256k1SubInternal(SB)

	LDt (r)
	CALL p256k1MulInternal(SB)

	LDt (s2)
	CALL p256k1SubInternal(SB)
	//ST (yout)
	MOVQ rptr, AX
    // Store y
    MOVQ acc4, (16*2 + 8*0)(AX)
    MOVQ acc5, (16*2 + 8*1)(AX)
    MOVQ acc6, (16*2 + 8*2)(AX)
    MOVQ acc7, (16*2 + 8*3)(AX)
	MOVQ $0, rptr

	RET
/* ---------------------------------------*/
#undef x1in
#undef y1in
#undef z1in
#undef x2in
#undef y2in
#undef xout
#undef yout
#undef zout
#undef s2
#undef z1sqr
#undef h
#undef r
#undef hsqr
#undef rsqr
#undef hcub
#undef rptr
#undef sel_save
#undef zero_save


// p256IsZero returns 1 in AX if [acc4..acc7] represents zero and zero
// otherwise. It writes to [acc4..acc7], t0 and t1.
TEXT p256k1IsZero(SB),NOSPLIT,$0
	// AX contains a flag that is set if the input is zero.
	XORQ AX, AX
	MOVQ $1, t1

	// Check whether [acc4..acc7] are all zero.
	MOVQ acc4, t0
	ORQ acc5, t0
	ORQ acc6, t0
	ORQ acc7, t0

	// Set the zero flag if so. (CMOV of a constant to a register doesn't
	// appear to be supported in Go. Thus t1 = 1.)
	CMOVQEQ t1, AX

	// XOR [acc4..acc7] with P and compare with zero again.
	XORQ p256k1p0<>(SB), acc4
	XORQ p256k1p1<>(SB), acc5
	XORQ p256k1p2<>(SB), acc6
	XORQ p256k1p3<>(SB), acc7
	ORQ acc5, acc4
	ORQ acc6, acc4
	ORQ acc7, acc4

	// Set the zero flag if so.
	CMOVQEQ t1, AX
	RET
/* ---------------------------------------*/
#define x1in(off) (32*0 + off)(SP)
#define y1in(off) (32*1 + off)(SP)
#define z1in(off) (32*2 + off)(SP)
#define x2in(off) (32*3 + off)(SP)
#define y2in(off) (32*4 + off)(SP)
#define z2in(off) (32*5 + off)(SP)

#define xout(off) (32*6 + off)(SP)
#define yout(off) (32*7 + off)(SP)
#define zout(off) (32*8 + off)(SP)

#define u1(off)    (32*9 + off)(SP)
#define u2(off)    (32*10 + off)(SP)
#define s1(off)    (32*11 + off)(SP)
#define s2(off)    (32*12 + off)(SP)
#define z1sqr(off) (32*13 + off)(SP)
#define z2sqr(off) (32*14 + off)(SP)
#define h(off)     (32*15 + off)(SP)
#define r(off)     (32*16 + off)(SP)
#define hsqr(off)  (32*17 + off)(SP)
#define rsqr(off)  (32*18 + off)(SP)
#define hcub(off)  (32*19 + off)(SP)
#define rptr       (32*20)(SP)
#define points_eq  (32*20+8)(SP)

//func p256k1PointAddAsm(res, in1, in2 []uint64) int
TEXT ·p256k1PointAddAsm(SB),0,$680-80
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in1+24(FP), BX
	MOVQ in2+48(FP), CX

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5

	MOVOU X0, x1in(16*0)
	MOVOU X1, x1in(16*1)
	MOVOU X2, y1in(16*0)
	MOVOU X3, y1in(16*1)
	MOVOU X4, z1in(16*0)
	MOVOU X5, z1in(16*1)

	MOVOU (16*0)(CX), X0
	MOVOU (16*1)(CX), X1
	MOVOU (16*2)(CX), X2
	MOVOU (16*3)(CX), X3
	MOVOU (16*4)(CX), X4
	MOVOU (16*5)(CX), X5

	MOVOU X0, x2in(16*0)
	MOVOU X1, x2in(16*1)
	MOVOU X2, y2in(16*0)
	MOVOU X3, y2in(16*1)
	MOVOU X4, z2in(16*0)
	MOVOU X5, z2in(16*1)
	// Store pointer to result
	MOVQ AX, rptr
	// Begin point add
	LDacc (z2in)
	CALL p256k1SqrInternal(SB)	// z2ˆ2
	ST (z2sqr)
	LDt (z2in)
	CALL p256k1MulInternal(SB)	// z2ˆ3
	LDt (y1in)
	CALL p256k1MulInternal(SB)	// s1 = z2ˆ3*y1
	ST (s1)

	LDacc (z1in)
	CALL p256k1SqrInternal(SB)	// z1ˆ2
	ST (z1sqr)
	LDt (z1in)
	CALL p256k1MulInternal(SB)	// z1ˆ3
	LDt (y2in)
	CALL p256k1MulInternal(SB)	// s2 = z1ˆ3*y2
	ST (s2)

	LDt (s1)
	CALL p256k1SubInternal(SB)	// r = s2 - s1
	ST (r)
	CALL p256k1IsZero(SB)
	MOVQ AX, points_eq

	LDacc (z2sqr)
	LDt (x1in)
	CALL p256k1MulInternal(SB)	// u1 = x1 * z2ˆ2
	ST (u1)
	LDacc (z1sqr)
	LDt (x2in)
	CALL p256k1MulInternal(SB)	// u2 = x2 * z1ˆ2
	ST (u2)

	LDt (u1)
	CALL p256k1SubInternal(SB)	// h = u2 - u1
	ST (h)
	CALL p256k1IsZero(SB)
	SHLQ $1, AX
	ORQ points_eq, AX
	MOVQ AX, points_eq

	LDacc (r)
	CALL p256k1SqrInternal(SB)	// rsqr = rˆ2
	ST (rsqr)

	LDacc (h)
	CALL p256k1SqrInternal(SB)	// hsqr = hˆ2
	ST (hsqr)

	LDt (h)
	CALL p256k1MulInternal(SB)	// hcub = hˆ3
	ST (hcub)

	LDt (s1)
	CALL p256k1MulInternal(SB)
	ST (s2)

	LDacc (z1in)
	LDt (z2in)
	CALL p256k1MulInternal(SB)	// z1 * z2
	LDt (h)
	CALL p256k1MulInternal(SB)	// z1 * z2 * h
	ST (zout)

	LDacc (hsqr)
	LDt (u1)
	CALL p256k1MulInternal(SB)	// hˆ2 * u1
	ST (u2)

	p256k1MulBy2Inline	// u1 * hˆ2 * 2, inline
	LDacc (rsqr)
	CALL p256k1SubInternal(SB)	// rˆ2 - u1 * hˆ2 * 2

	LDt (hcub)
	CALL p256k1SubInternal(SB)
	ST (xout)

	MOVQ acc4, t0
	MOVQ acc5, t1
	MOVQ acc6, t2
	MOVQ acc7, t3
	LDacc (u2)
	CALL p256k1SubInternal(SB)

	LDt (r)
	CALL p256k1MulInternal(SB)

	LDt (s2)
	CALL p256k1SubInternal(SB)
	ST (yout)

	MOVOU xout(16*0), X0
	MOVOU xout(16*1), X1
	MOVOU yout(16*0), X2
	MOVOU yout(16*1), X3
	MOVOU zout(16*0), X4
	MOVOU zout(16*1), X5
	// Finally output the result
	MOVQ rptr, AX
	MOVQ $0, rptr
	MOVOU X0, (16*0)(AX)
	MOVOU X1, (16*1)(AX)
	MOVOU X2, (16*2)(AX)
	MOVOU X3, (16*3)(AX)
	MOVOU X4, (16*4)(AX)
	MOVOU X5, (16*5)(AX)

	MOVQ points_eq, AX
	MOVQ AX, ret+72(FP)

	RET
#undef x1in
#undef y1in
#undef z1in
#undef x2in
#undef y2in
#undef z2in
#undef xout
#undef yout
#undef zout
#undef s1
#undef s2
#undef u1
#undef u2
#undef z1sqr
#undef z2sqr
#undef h
#undef r
#undef hsqr
#undef rsqr
#undef hcub
#undef rptr
/* ---------------------------------------*/
#define x(off) (32*0 + off)(SP)
#define y(off) (32*1 + off)(SP)
#define z(off) (32*2 + off)(SP)
#define a(off) (32*2 + off)(SP) //reuse till z is useless
#define b(off) (32*1 + off)(SP) //reuse till y is useless
#define d(off) (32*0 + off)(SP) //reuse till x is useless
#define e(off) (32*2 + off)(SP) //reuse till a is useless
#define f(off) (32*1 + off)(SP) //reuse till b is useless

#define c(off)	(32*3 + off)(SP)
#define c8(off)	(32*4 + off)(SP)
#define zsqr(off) (32*5 + off)(SP)
#define debug(off)  (32*6 + off)(SP)
#define rptr	  (32*7)(SP)

//func p256k1PointDoubleAsm(res, in []uint64)
TEXT ·p256k1PointDoubleAsm(SB),NOSPLIT,$256-48
	// Move input to stack in order to free registers
	MOVQ res+0(FP), AX
	MOVQ in+24(FP), BX

	MOVOU (16*0)(BX), X0
	MOVOU (16*1)(BX), X1
	MOVOU (16*2)(BX), X2
	MOVOU (16*3)(BX), X3
	MOVOU (16*4)(BX), X4
	MOVOU (16*5)(BX), X5

	MOVOU X0, x(16*0)
	MOVOU X1, x(16*1)
	MOVOU X2, y(16*0)
	MOVOU X3, y(16*1)
	MOVOU X4, z(16*0)
	MOVOU X5, z(16*1)
	// Store pointer to result
	MOVQ AX, rptr
	// Begin point double
	LDacc (z)
    LDt (y)
    CALL p256k1MulInternal(SB)
    p256k1MulBy2Inline
    MOVQ rptr, AX
    // Store z
    MOVQ t0, (16*4 + 8*0)(AX)
    MOVQ t1, (16*4 + 8*1)(AX)
    MOVQ t2, (16*4 + 8*2)(AX)
    MOVQ t3, (16*4 + 8*3)(AX)
    // z is useless now, we can use a for A
    LDacc (x)
	CALL p256k1SqrInternal(SB) // A = x ^ 2
	ST (a)

    LDacc (y)
    CALL p256k1SqrInternal(SB) // B = y ^ 2
    ST (b) // y is useless now, we can use b for B

	CALL p256k1SqrInternal(SB) // C = B ^ 2
	ST (c)
	p256k1MulBy2Inline // tmp = C * 2
	t2acc
	p256k1MulBy2Inline // tmp = C * 2 * 2
	t2acc
	p256k1MulBy2Inline // tmp = C * 2 * 2 * 2 = 8 * C
	STt(c8)

	LDacc (b)
	LDt(x)
    p256k1AddInline // tmp = x + B
    t2acc
    CALL p256k1SqrInternal(SB) // tmp = (x + B) ^ 2
    LDt (a)
    CALL p256k1SubInternal(SB) // tmp = (x + B) ^ 2 - A
    LDt (c)
	CALL p256k1SubInternal(SB) // tmp = (x + B) ^ 2 - A - C
	p256k1MulBy2Inline         // D = 2 * ((x + B) ^ 2 - A - C)
	STt (d) // x is useless now, we can use d for D

	LDacc (a)
	p256k1MulBy2Inline // tmp = A * 2
	LDacc (a)
	p256k1AddInline    // E = A * 2 + A = 3 * A
	t2acc
    ST (e) // a is uselsee now, we can use e for E

    CALL p256k1SqrInternal(SB) // F = E ^ 2
    ST (f) // b is uselsee now, we can use f for F

    LDt (d)
    CALL p256k1SubInternal(SB) // tmp = F - D
    CALL p256k1SubInternal(SB) // tmp = F - D - D = F - 2 * D

    //delete
    //LDacc (debug)
    //delete
    MOVQ rptr, AX
    // Store x
    MOVQ acc4, (16*0 + 8*0)(AX)
    MOVQ acc5, (16*0 + 8*1)(AX)
    MOVQ acc6, (16*0 + 8*2)(AX)
    MOVQ acc7, (16*0 + 8*3)(AX)

	acc2t
	LDacc (d)
	CALL p256k1SubInternal(SB) // tmp = D - X3
	LDt (e)
	CALL p256k1MulInternal(SB) // tmp = E * (D - X3)
	LDt (c8)
	CALL p256k1SubInternal(SB) // tmp = E * (D - X3) - 8 * C

	MOVQ rptr, AX
    // Store y
    MOVQ acc4, (16*2 + 8*0)(AX)
    MOVQ acc5, (16*2 + 8*1)(AX)
    MOVQ acc6, (16*2 + 8*2)(AX)
    MOVQ acc7, (16*2 + 8*3)(AX)

	///////////////////////
	MOVQ $0, rptr

	RET
/* ---------------------------------------*/
#undef x
#undef y
#undef z
#undef zsqr
#undef debug
#undef rptr
#define u(off) (32*0 + off)(SP)
#define v(off) (32*1 + off)(SP)
#define s(off) (32*2 + off)(SP)

#define r(off)	(32*3 + off)(SP)
#define debug(off)	(32*4 + off)(SP)
#define alt(off) (32*5 + off)(SP)
#define tmp(off)  (32*6 + off)(SP)
#define rptr	  (32*7)(SP)
//func p256k1MontInversePhase1(res, in []uint64, k *uint64)
TEXT ·p256k1MontInversePhase1(SB),NOSPLIT,$256-48
    MOVQ res+0(FP), AX
    MOVQ in+24(FP), DX
    MOVQ AX, rptr
    MOVQ p256k1p0<>(SB), acc4 // u
    MOVQ p256k1p1<>(SB), acc5
    MOVQ p256k1p2<>(SB), acc6
    MOVQ p256k1p3<>(SB), acc7

    MOVQ (8*0)(DX), acc0 // v
    MOVQ (8*1)(DX), acc1
    MOVQ (8*2)(DX), acc2
    MOVQ (8*3)(DX), acc3
    MOVQ $0, DX
    MOVQ $0, t0
    MOVQ $0, t1
    MOVQ $0, t2
    MOVQ $0, t3
    STt (r)
    MOVQ $1, t0
    STt (s)
    MOVQ $0, hlp
phase1loop:
    CMPQ acc0, $0
    JNZ phase1body
    CMPQ acc1, $0
    JNZ phase1body
    CMPQ acc2, $0
    JNZ phase1body
    CMPQ acc3, $0
    JZ phase1final

phase1body:
    //LDt (s)
ushiftloop:

    TESTQ $7, acc4
    JNZ ushift2

    SHRQ $3, acc5, acc4
    SHRQ $3, acc6, acc5
    SHRQ $3, acc7, acc6
    SHRQ $3, acc7

    SHLQ $3, t2, t3
    SHLQ $3, t1, t2
    SHLQ $3, t0, t1
    SHLQ $3, t0
    ADDQ $3, hlp
    JMP ushiftloop

ushift2:
    TESTQ $3, acc4
    JNZ ushift1

    SHRQ $2, acc5, acc4
    SHRQ $2, acc6, acc5
    SHRQ $2, acc7, acc6
    SHRQ $2, acc7

    SHLQ $2, t2, t3
    SHLQ $2, t1, t2
    SHLQ $2, t0, t1
    SHLQ $2, t0

    ADDQ $2, hlp
    JMP ushiftloop

ushift1:
    TESTQ $1, acc4
    JNZ vshift

    SHRQ $1, acc5, acc4
    SHRQ $1, acc6, acc5
    SHRQ $1, acc7, acc6
    SHRQ $1, acc7

    SHLQ $1, t2, t3
    SHLQ $1, t1, t2
    SHLQ $1, t0, t1
    SHLQ $1, t0


    INCQ hlp
    JMP ushiftloop
vshift:
    STt (s)
    LDt (r)
vshiftloop:

    TESTQ $7, acc0
    JNZ vshift2

    SHRQ $3, acc1, acc0
    SHRQ $3, acc2, acc1
    SHRQ $3, acc3, acc2
    SHRQ $3, acc3

    SHLQ $3, t2, t3
    SHLQ $3, t1, t2
    SHLQ $3, t0, t1
    SHLQ $3, t0

    ADDQ $3, hlp
    JMP vshiftloop
vshift2:

    TESTQ $3, acc0
    JNZ vshift1

    SHRQ $2, acc1, acc0
    SHRQ $2, acc2, acc1
    SHRQ $2, acc3, acc2
    SHRQ $2, acc3

    SHLQ $2, t2, t3
    SHLQ $2, t1, t2
    SHLQ $2, t0, t1
    SHLQ $2, t0

    ADDQ $2, hlp
    JMP vshiftloop

vshift1:
    TESTQ $1, acc0
    JNZ diff

    SHRQ $1, acc1, acc0
    SHRQ $1, acc2, acc1
    SHRQ $1, acc3, acc2
    SHRQ $1, acc3

    ADDQ t0, t0
    ADCQ t1, t1
    ADCQ t2, t2
    ADCQ t3, t3

    INCQ hlp
    JMP vshiftloop
diff:
    STt (r)
    MOVQ acc0, t0
    MOVQ acc1, t1
    MOVQ acc2, t2
    MOVQ acc3, t3
    SUBQ acc4, t0
    SBBQ acc5, t1
    SBBQ acc6, t2
    SBBQ acc7, t3
    JB ularger
    MOVQ t0, acc0
    MOVQ t1, acc1
    MOVQ t2, acc2
    MOVQ t3, acc3
    SHRQ $1, acc1, acc0
    SHRQ $1, acc2, acc1
    SHRQ $1, acc3, acc2
    SHRQ $1, acc3
    ST (u)
    LDacc (r)
    LDt (s)
    ADDQ acc4, t0
    ADCQ acc5, t1
    ADCQ acc6, t2
    ADCQ acc7, t3
    //STt (s)
    ADDQ acc4, acc4
    ADCQ acc5, acc5
    ADCQ acc6, acc6
    ADCQ acc7, acc7
    ADCQ $0, DX

    //SHLQ $1, acc6, acc7
    //SHLQ $1, acc5, acc6
    //SHLQ $1, acc4, acc5
    //SHLQ $1, acc4
    ST (r)
    LDacc (u)
    INCQ hlp
    JMP phase1loop
ularger:
    SUBQ acc0, acc4
    SBBQ acc1, acc5
    SBBQ acc2, acc6
    SBBQ acc3, acc7
    SHRQ $1, acc5, acc4
    SHRQ $1, acc6, acc5
    SHRQ $1, acc7, acc6
    SHRQ $1, acc7
    ST (u)
    LDacc (r)
    LDt (s)
    ADDQ t0, acc4
    ADCQ t1, acc5
    ADCQ t2, acc6
    ADCQ t3, acc7
    ST (r)
    SHLQ $1, t2, t3
    SHLQ $1, t1, t2
    SHLQ $1, t0, t1
    SHLQ $1, t0
    //STt (s)
    LDacc (u)
    INCQ hlp
    JMP phase1loop

phase1final:
    LDacc (r)
    //ADCQ $0, DX

    SUBQ p256k1p0<>(SB), acc4
    SBBQ p256k1p1<>(SB), acc5
    SBBQ p256k1p2<>(SB), acc6
    SBBQ p256k1p3<>(SB), acc7
    SBBQ $0, DX
    JNB phase1return
    LDacc (r)
phase1return:
    MOVQ p256k1p0<>(SB), acc0
    MOVQ p256k1p1<>(SB), acc1
    MOVQ p256k1p2<>(SB), acc2
    MOVQ p256k1p3<>(SB), acc3
    SUBQ acc4, acc0
    SBBQ acc5, acc1
    SBBQ acc6, acc2
    SBBQ acc7, acc3

    MOVQ acc0, (8*0)(AX)
    MOVQ acc1, (8*1)(AX)
    MOVQ acc2, (8*2)(AX)
    MOVQ acc3, (8*3)(AX)

    MOVQ k+48(FP), AX
    MOVQ hlp, (0)(AX)
    MOVQ $0, rptr
	RET
/* ---------------------------------------*/
//func p256k1OrdMontInversePhase1(res, in []uint64, k *uint64)
TEXT ·p256k1OrdMontInversePhase1(SB),NOSPLIT,$256-48
    MOVQ res+0(FP), AX
    MOVQ in+24(FP), DX
    MOVQ AX, rptr
    MOVQ p256k1ord<>+0x00(SB), acc4 // u
    MOVQ p256k1ord<>+0x08(SB), acc5
    MOVQ p256k1ord<>+0x10(SB), acc6
    MOVQ p256k1ord<>+0x18(SB), acc7

    MOVQ (8*0)(DX), acc0 // v
    MOVQ (8*1)(DX), acc1
    MOVQ (8*2)(DX), acc2
    MOVQ (8*3)(DX), acc3
    MOVQ $0, DX
    MOVQ $0, t0
    MOVQ $0, t1
    MOVQ $0, t2
    MOVQ $0, t3
    STt (r)
    MOVQ $1, t0
    STt (s)
    MOVQ $0, hlp
phase1loop:
    CMPQ acc0, $0
    JNZ phase1body
    CMPQ acc1, $0
    JNZ phase1body
    CMPQ acc2, $0
    JNZ phase1body
    CMPQ acc3, $0
    JZ phase1final

phase1body:
    //LDt (s)
ushiftloop:

    TESTQ $7, acc4
    JNZ ushift2

    SHRQ $3, acc5, acc4
    SHRQ $3, acc6, acc5
    SHRQ $3, acc7, acc6
    SHRQ $3, acc7

    SHLQ $3, t2, t3
    SHLQ $3, t1, t2
    SHLQ $3, t0, t1
    SHLQ $3, t0
    ADDQ $3, hlp
    JMP ushiftloop

ushift2:
    TESTQ $3, acc4
    JNZ ushift1

    SHRQ $2, acc5, acc4
    SHRQ $2, acc6, acc5
    SHRQ $2, acc7, acc6
    SHRQ $2, acc7

    SHLQ $2, t2, t3
    SHLQ $2, t1, t2
    SHLQ $2, t0, t1
    SHLQ $2, t0

    ADDQ $2, hlp
    JMP ushiftloop

ushift1:
    TESTQ $1, acc4
    JNZ vshift

    SHRQ $1, acc5, acc4
    SHRQ $1, acc6, acc5
    SHRQ $1, acc7, acc6
    SHRQ $1, acc7

    SHLQ $1, t2, t3
    SHLQ $1, t1, t2
    SHLQ $1, t0, t1
    SHLQ $1, t0


    INCQ hlp
    JMP ushiftloop
vshift:
    STt (s)
    LDt (r)
vshiftloop:

    TESTQ $7, acc0
    JNZ vshift2

    SHRQ $3, acc1, acc0
    SHRQ $3, acc2, acc1
    SHRQ $3, acc3, acc2
    SHRQ $3, acc3

    SHLQ $3, t2, t3
    SHLQ $3, t1, t2
    SHLQ $3, t0, t1
    SHLQ $3, t0

    ADDQ $3, hlp
    JMP vshiftloop
vshift2:

    TESTQ $3, acc0
    JNZ vshift1

    SHRQ $2, acc1, acc0
    SHRQ $2, acc2, acc1
    SHRQ $2, acc3, acc2
    SHRQ $2, acc3

    SHLQ $2, t2, t3
    SHLQ $2, t1, t2
    SHLQ $2, t0, t1
    SHLQ $2, t0

    ADDQ $2, hlp
    JMP vshiftloop

vshift1:
    TESTQ $1, acc0
    JNZ diff

    SHRQ $1, acc1, acc0
    SHRQ $1, acc2, acc1
    SHRQ $1, acc3, acc2
    SHRQ $1, acc3

    ADDQ t0, t0
    ADCQ t1, t1
    ADCQ t2, t2
    ADCQ t3, t3

    INCQ hlp
    JMP vshiftloop
diff:
    STt (r)
    MOVQ acc0, t0
    MOVQ acc1, t1
    MOVQ acc2, t2
    MOVQ acc3, t3
    SUBQ acc4, t0
    SBBQ acc5, t1
    SBBQ acc6, t2
    SBBQ acc7, t3
    JB ularger
    MOVQ t0, acc0
    MOVQ t1, acc1
    MOVQ t2, acc2
    MOVQ t3, acc3
    SHRQ $1, acc1, acc0
    SHRQ $1, acc2, acc1
    SHRQ $1, acc3, acc2
    SHRQ $1, acc3
    ST (u)
    LDacc (r)
    LDt (s)
    ADDQ acc4, t0
    ADCQ acc5, t1
    ADCQ acc6, t2
    ADCQ acc7, t3
    //STt (s)
    ADDQ acc4, acc4
    ADCQ acc5, acc5
    ADCQ acc6, acc6
    ADCQ acc7, acc7
    ADCQ $0, DX

    //SHLQ $1, acc6, acc7
    //SHLQ $1, acc5, acc6
    //SHLQ $1, acc4, acc5
    //SHLQ $1, acc4
    ST (r)
    LDacc (u)
    INCQ hlp
    JMP phase1loop
ularger:
    SUBQ acc0, acc4
    SBBQ acc1, acc5
    SBBQ acc2, acc6
    SBBQ acc3, acc7
    SHRQ $1, acc5, acc4
    SHRQ $1, acc6, acc5
    SHRQ $1, acc7, acc6
    SHRQ $1, acc7
    ST (u)
    LDacc (r)
    LDt (s)
    ADDQ t0, acc4
    ADCQ t1, acc5
    ADCQ t2, acc6
    ADCQ t3, acc7
    ST (r)
    SHLQ $1, t2, t3
    SHLQ $1, t1, t2
    SHLQ $1, t0, t1
    SHLQ $1, t0
    //STt (s)
    LDacc (u)
    INCQ hlp
    JMP phase1loop

phase1final:
    LDacc (r)
    //ADCQ $0, DX

    SUBQ p256k1ord<>+0x00(SB), acc4
    SBBQ p256k1ord<>+0x08(SB), acc5
    SBBQ p256k1ord<>+0x10(SB), acc6
    SBBQ p256k1ord<>+0x18(SB), acc7
    SBBQ $0, DX
    JNB phase1return
    LDacc (r)
phase1return:
    MOVQ p256k1ord<>+0x00(SB), acc0
    MOVQ p256k1ord<>+0x08(SB), acc1
    MOVQ p256k1ord<>+0x10(SB), acc2
    MOVQ p256k1ord<>+0x18(SB), acc3
    SUBQ acc4, acc0
    SBBQ acc5, acc1
    SBBQ acc6, acc2
    SBBQ acc7, acc3

    MOVQ acc0, (8*0)(AX)
    MOVQ acc1, (8*1)(AX)
    MOVQ acc2, (8*2)(AX)
    MOVQ acc3, (8*3)(AX)

    MOVQ k+48(FP), AX
    MOVQ hlp, (0)(AX)
    MOVQ $0, rptr
	RET
/* ---------------------------------------*/