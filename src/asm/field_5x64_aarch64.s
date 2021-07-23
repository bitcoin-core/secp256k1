/* Aarch64 assembly, created by disassembling the output of GCC 10.3.0 from the C __int128
 * based implementation in src/field_5x64_impl.h. */

	.text

/* Aarch64 assembly modules, created by disassembling the 
   output of high level c function written by Kaushik */

	.p2align 4
	.global secp256k1_fe_mul_45to5
	.type	secp256k1_fe_mul_45to5, %function
secp256k1_fe_mul_45to5:
	stp	x29, x30, [sp, #-16]!
	mov	x8, #0x3d1                 	// #977
	movk	x8, #0x1, lsl #32
	mov	x29, sp
	ldp	x7, x3, [x2, #24]
	ldp	x6, x5, [x2]
	ldp	x10, x9, [x1]
	mul	x4, x3, x8
	umulh	x3, x3, x8
	adds	x4, x4, x6
	cinc	x3, x3, cs  // cs = hs, nlast
	ldr	x6, [x2, #16]
	adds	x5, x5, x3
	cset	x3, cs  // cs = hs, nlast
	adds	x6, x6, x3
	cset	x2, cs  // cs = hs, nlast
	adds	x7, x7, x2
	cset	x2, cs  // cs = hs, nlast
	mul	x18, x9, x6
	ldp	x12, x15, [x1, #16]
	mul	x14, x9, x7
	mul	x11, x2, x8
	umulh	x2, x2, x8
	adds	x11, x11, x4
	umulh	x4, x10, x7
	adc	x5, x5, x2
	umulh	x2, x9, x6
	mul	x3, x12, x6
	mul	x17, x10, x7
	adds	x2, x2, x3
	mul	x13, x15, x5
	umulh	x1, x12, x5
	cset	x3, cs  // cs = hs, nlast
	adds	x4, x4, x14
	cset	x14, cs  // cs = hs, nlast
	adds	x2, x2, x4
	adc	x3, x3, x14
	umulh	x4, x15, x11
	adds	x1, x1, x13
	mul	x14, x10, x11
	cset	x13, cs  // cs = hs, nlast
	adds	x2, x2, x1
	adc	x3, x3, x13
	adds	x2, x2, x4
	cinc	x3, x3, cs  // cs = hs, nlast
	mul	x13, x15, x6
	umulh	x1, x12, x6
	mul	x4, x2, x8
	umulh	x2, x2, x8
	madd	x2, x3, x8, x2
	adds	x4, x4, x14
	umulh	x3, x9, x7
	str	x4, [x0]
	mul	x14, x12, x7
	cinc	x2, x2, cs  // cs = hs, nlast
	adds	x1, x1, x13
	umulh	x13, x15, x5
	cset	x4, cs  // cs = hs, nlast
	adds	x3, x3, x14
	cset	x14, cs  // cs = hs, nlast
	adds	x1, x1, x3
	adc	x4, x4, x14
	adds	x1, x1, x13
	cinc	x4, x4, cs  // cs = hs, nlast
	umulh	x3, x15, x7
	mul	x13, x5, x10
	umulh	x14, x1, x8
	mul	x1, x1, x8
	madd	x14, x4, x8, x14
	adds	x1, x1, x13
	umulh	x4, x10, x11
	mul	x13, x9, x11
	cinc	x14, x14, cs  // cs = hs, nlast
	adds	x16, x4, x13
	mul	x4, x3, x8
	umulh	x13, x3, x8
	cset	x30, cs  // cs = hs, nlast
	adds	x3, x1, x16
	umulh	x16, x10, x6
	adc	x14, x14, x30
	adds	x4, x4, x17
	umulh	x1, x12, x11
	cinc	x13, x13, cs  // cs = hs, nlast
	mul	x17, x15, x11
	adds	x16, x16, x18
	cset	x30, cs  // cs = hs, nlast
	adds	x4, x4, x16
	mul	x18, x12, x5
	adc	x13, x13, x30
	umulh	x16, x9, x5
	adds	x17, x1, x17
	cset	x30, cs  // cs = hs, nlast
	adds	x4, x4, x17
	umulh	x1, x12, x7
	adc	x13, x13, x30
	mul	x7, x15, x7
	adds	x16, x16, x18
	umulh	x15, x15, x6
	cset	x17, cs  // cs = hs, nlast
	adds	x4, x4, x16
	umulh	x16, x9, x11
	adc	x13, x13, x17
	adds	x1, x1, x7
	cset	x7, cs  // cs = hs, nlast
	adds	x1, x1, x15
	cinc	x15, x7, cs  // cs = hs, nlast
	mul	x12, x12, x11
	mul	x6, x10, x6
	umulh	x7, x1, x8
	mul	x1, x1, x8
	madd	x7, x15, x8, x7
	adds	x1, x1, x16
	mul	x9, x9, x5
	cinc	x7, x7, cs  // cs = hs, nlast
	umulh	x5, x5, x10
	adds	x6, x6, x12
	cset	x8, cs  // cs = hs, nlast
	adds	x1, x1, x6
	adc	x7, x7, x8
	adds	x5, x5, x9
	cset	x6, cs  // cs = hs, nlast
	adds	x1, x1, x5
	adc	x7, x7, x6
	adds	x2, x2, x3
	cinc	x14, x14, cs  // cs = hs, nlast
	adds	x1, x1, x14
	stp	x2, x1, [x0, #8]
	cinc	x7, x7, cs  // cs = hs, nlast
	adds	x4, x4, x7
	cinc	x13, x13, cs  // cs = hs, nlast
	stp	x4, x13, [x0, #24]
	ldp	x29, x30, [sp], #16
	ret
	.size secp256k1_fe_mul_45to5, .-secp256k1_fe_mul_45to5

	.p2align 4
	.global secp256k1_fe_mul_55to5
	.type	secp256k1_fe_mul_55to5, %function
secp256k1_fe_mul_55to5:
	stp	x29, x30, [sp, #-32]!
	mov	x9, #0x3d1                 	// #977
	movk	x9, #0x1, lsl #32
	mov	x29, sp
	ldp	x5, x10, [x1]
	stp	x19, x20, [sp, #16]
	ldr	x3, [x1, #32]
	ldp	x12, x8, [x1, #16]
	mul	x4, x3, x9
	umulh	x3, x3, x9
	adds	x4, x4, x5
	cinc	x3, x3, cs  // cs = hs, nlast
	adds	x10, x10, x3
	cset	x3, cs  // cs = hs, nlast
	adds	x12, x12, x3
	cset	x1, cs  // cs = hs, nlast
	adds	x8, x8, x1
	cset	x3, cs  // cs = hs, nlast
	ldp	x7, x11, [x2]
	ldr	x1, [x2, #32]
	mul	x6, x3, x9
	umulh	x5, x3, x9
	adds	x6, x6, x4
	mul	x3, x1, x9
	adc	x10, x10, x5
	umulh	x1, x1, x9
	adds	x3, x3, x7
	cinc	x1, x1, cs  // cs = hs, nlast
	ldr	x13, [x2, #16]
	adds	x11, x11, x1
	cset	x1, cs  // cs = hs, nlast
	ldr	x7, [x2, #24]
	adds	x13, x13, x1
	cset	x1, cs  // cs = hs, nlast
	adds	x7, x7, x1
	cset	x1, cs  // cs = hs, nlast
	mul	x19, x12, x13
	umulh	x14, x10, x13
	mul	x18, x10, x7
	mul	x5, x1, x9
	umulh	x1, x1, x9
	adds	x5, x5, x3
	umulh	x17, x7, x6
	adc	x11, x11, x1
	mul	x16, x7, x12
	umulh	x1, x12, x13
	umulh	x2, x8, x5
	umulh	x4, x11, x12
	mul	x15, x11, x8
	adds	x2, x2, x19
	cset	x3, cs  // cs = hs, nlast
	mul	x19, x6, x5
	adds	x15, x4, x15
	umulh	x4, x11, x8
	cset	x20, cs  // cs = hs, nlast
	adds	x2, x2, x15
	adc	x3, x3, x20
	adds	x14, x14, x18
	cset	x15, cs  // cs = hs, nlast
	adds	x2, x2, x14
	adc	x3, x3, x15
	adds	x2, x2, x17
	cinc	x3, x3, cs  // cs = hs, nlast
	mul	x18, x13, x8
	umulh	x17, x10, x7
	mul	x14, x2, x9
	umulh	x2, x2, x9
	madd	x2, x3, x9, x2
	adds	x14, x14, x19
	str	x14, [x0]
	mul	x15, x10, x5
	cinc	x2, x2, cs  // cs = hs, nlast
	adds	x1, x1, x16
	cset	x3, cs  // cs = hs, nlast
	adds	x4, x4, x18
	cset	x14, cs  // cs = hs, nlast
	adds	x1, x1, x4
	adc	x4, x3, x14
	adds	x1, x1, x17
	cinc	x4, x4, cs  // cs = hs, nlast
	mul	x17, x11, x6
	umulh	x3, x6, x5
	umulh	x14, x1, x9
	mul	x1, x1, x9
	madd	x14, x4, x9, x14
	umulh	x16, x7, x8
	adds	x1, x1, x15
	umulh	x4, x12, x5
	cinc	x14, x14, cs  // cs = hs, nlast
	mul	x15, x8, x5
	adds	x3, x3, x17
	cset	x18, cs  // cs = hs, nlast
	mul	x17, x7, x6
	adds	x3, x1, x3
	umulh	x1, x13, x6
	adc	x14, x14, x18
	adds	x4, x4, x15
	mul	x19, x11, x12
	cset	x15, cs  // cs = hs, nlast
	adds	x18, x1, x17
	mul	x1, x16, x9
	umulh	x17, x16, x9
	cset	x20, cs  // cs = hs, nlast
	adds	x4, x4, x18
	mul	x30, x10, x13
	umulh	x16, x10, x11
	adc	x15, x15, x20
	adds	x18, x1, x19
	umulh	x1, x13, x8
	cinc	x17, x17, cs  // cs = hs, nlast
	adds	x4, x4, x18
	mul	x8, x7, x8
	adc	x15, x15, x17
	adds	x16, x16, x30
	umulh	x7, x7, x12
	cset	x17, cs  // cs = hs, nlast
	adds	x4, x4, x16
	adc	x15, x15, x17
	adds	x1, x1, x8
	cset	x8, cs  // cs = hs, nlast
	adds	x1, x1, x7
	cinc	x8, x8, cs  // cs = hs, nlast
	mul	x13, x13, x6
	mul	x12, x12, x5
	umulh	x7, x1, x9
	mul	x1, x1, x9
	madd	x7, x8, x9, x7
	umulh	x6, x11, x6
	adds	x1, x1, x13
	umulh	x5, x10, x5
	cinc	x7, x7, cs  // cs = hs, nlast
	mul	x10, x10, x11
	adds	x6, x6, x12
	cset	x8, cs  // cs = hs, nlast
	adds	x1, x1, x6
	adc	x7, x7, x8
	adds	x5, x5, x10
	cset	x6, cs  // cs = hs, nlast
	adds	x1, x1, x5
	adc	x7, x7, x6
	adds	x2, x2, x3
	cinc	x14, x14, cs  // cs = hs, nlast
	adds	x1, x1, x14
	stp	x2, x1, [x0, #8]
	cinc	x7, x7, cs  // cs = hs, nlast
	adds	x4, x4, x7
	cinc	x15, x15, cs  // cs = hs, nlast
	stp	x4, x15, [x0, #24]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret
	.size secp256k1_fe_mul_55to5, .-secp256k1_fe_mul_55to5

	.p2align 4
	.global secp256k1_fe_sqr_5to5
	.type secp256k1_fe_sqr_5to5, %function
secp256k1_fe_sqr_5to5:
	stp	x29, x30, [sp, #-16]!
	mov	x6, #0x3d1                 	// #977
	movk	x6, #0x1, lsl #32
	mov	x29, sp
	ldp	x5, x4, [x1]
	ldr	x2, [x1, #32]
	mul	x3, x2, x6
	umulh	x2, x2, x6
	adds	x5, x3, x5
	cinc	x2, x2, cs  // cs = hs, nlast
	adds	x4, x4, x2
	ldp	x3, x2, [x1, #16]
	cset	x7, cs  // cs = hs, nlast
	adds	x3, x3, x7
	cset	x1, cs  // cs = hs, nlast
	adds	x2, x2, x1
	cset	x7, cs  // cs = hs, nlast
	mul	x13, x3, x3
	umulh	x14, x3, x3
	umulh	x15, x2, x3
	mul	x1, x7, x6
	umulh	x7, x7, x6
	adds	x1, x1, x5
	mul	x17, x2, x2
	adc	x4, x4, x7
	lsl	x5, x15, #1
	lsr	x15, x15, #63
	mul	x16, x2, x3
	umulh	x8, x2, x1
	mul	x10, x4, x2
	umulh	x7, x4, x3
	mul	x9, x4, x1
	adds	x7, x7, x10
	mul	x12, x1, x1
	cset	x11, cs  // cs = hs, nlast
	adds	x8, x7, x8
	cinc	x11, x11, cs  // cs = hs, nlast
	umulh	x30, x1, x1
	lsl	x7, x8, #1
	lsl	x10, x9, #1
	adds	x7, x7, x13
	extr	x8, x11, x8, #63
	cinc	x8, x8, cs  // cs = hs, nlast
	lsr	x9, x9, #63
	mul	x18, x4, x4
	mul	x11, x7, x6
	umulh	x7, x7, x6
	madd	x7, x8, x6, x7
	adds	x11, x11, x12
	str	x11, [x0]
	umulh	x13, x4, x2
	cinc	x7, x7, cs  // cs = hs, nlast
	adds	x10, x10, x30
	cinc	x9, x9, cs  // cs = hs, nlast
	adds	x5, x5, x17
	cinc	x8, x15, cs  // cs = hs, nlast
	mul	x17, x3, x1
	mul	x15, x2, x1
	umulh	x11, x5, x6
	mul	x5, x5, x6
	madd	x11, x8, x6, x11
	adds	x5, x5, x18
	umulh	x12, x4, x1
	cinc	x11, x11, cs  // cs = hs, nlast
	adds	x13, x13, x16
	cset	x8, cs  // cs = hs, nlast
	mul	x16, x4, x3
	umulh	x1, x3, x1
	lsl	x3, x13, #1
	adds	x3, x3, x14
	extr	x8, x8, x13, #63
	cinc	x14, x8, cs  // cs = hs, nlast
	umulh	x2, x2, x2
	umulh	x4, x4, x4
	mul	x13, x3, x6
	umulh	x3, x3, x6
	madd	x3, x14, x6, x3
	adds	x13, x13, x7
	mul	x8, x2, x6
	cinc	x3, x3, cs  // cs = hs, nlast
	adds	x10, x10, x13
	adc	x9, x9, x3
	adds	x12, x12, x17
	cset	x3, cs  // cs = hs, nlast
	umulh	x2, x2, x6
	lsl	x6, x12, #1
	adds	x6, x6, x9
	extr	x3, x3, x12, #63
	cinc	x3, x3, cs  // cs = hs, nlast
	adds	x5, x5, x6
	adc	x11, x11, x3
	adds	x1, x1, x15
	cset	x3, cs  // cs = hs, nlast
	adds	x1, x1, x16
	cinc	x3, x3, cs  // cs = hs, nlast
	stp	x10, x5, [x0, #8]
	lsl	x5, x1, #1
	adds	x5, x5, x11
	extr	x1, x3, x1, #63
	cinc	x1, x1, cs  // cs = hs, nlast
	adds	x4, x8, x4
	cinc	x2, x2, cs  // cs = hs, nlast
	adds	x4, x4, x5
	adc	x2, x1, x2
	stp	x4, x2, [x0, #24]
	ldp	x29, x30, [sp], #16
	ret
	nop
	.size secp256k1_fe_sqr_5to5, .-secp256k1_fe_sqr_5to5

	.p2align 4
	.global secp256k1_fe_mul_44to5
	.type	secp256k1_fe_mul_44to5, %function
secp256k1_fe_mul_44to5:
	stp	x29, x30, [sp, #-32]!
	mov	x9, #0x3d1                 	// #977
	movk	x9, #0x1, lsl #32
	mov	x29, sp
	ldp	x10, x6, [x1]
	ldp	x11, x15, [x1, #16]
	ldp	x5, x12, [x2, #16]
	ldp	x7, x8, [x2]
	str	x19, [sp, #16]
	mul	x13, x11, x5
	mul	x3, x6, x12
	umulh	x4, x12, x10
	adds	x1, x3, x13
	mul	x13, x15, x8
	umulh	x2, x6, x5
	cset	x3, cs  // cs = hs, nlast
	adds	x4, x4, x13
	umulh	x13, x11, x8
	cset	x14, cs  // cs = hs, nlast
	adds	x1, x1, x4
	adc	x3, x3, x14
	umulh	x4, x15, x7
	adds	x2, x2, x13
	mul	x14, x10, x7
	cset	x13, cs  // cs = hs, nlast
	adds	x1, x1, x2
	adc	x3, x3, x13
	adds	x1, x1, x4
	cinc	x3, x3, cs  // cs = hs, nlast
	umulh	x13, x11, x5
	umulh	x2, x6, x12
	mul	x4, x1, x9
	umulh	x1, x1, x9
	madd	x1, x3, x9, x1
	adds	x4, x4, x14
	umulh	x3, x15, x8
	str	x4, [x0]
	mul	x14, x12, x11
	cinc	x1, x1, cs  // cs = hs, nlast
	adds	x2, x2, x13
	mul	x13, x5, x15
	cset	x4, cs  // cs = hs, nlast
	adds	x3, x3, x14
	cset	x14, cs  // cs = hs, nlast
	adds	x2, x2, x3
	adc	x4, x4, x14
	adds	x2, x2, x13
	cinc	x4, x4, cs  // cs = hs, nlast
	mul	x16, x6, x7
	mul	x14, x8, x10
	umulh	x13, x2, x9
	mul	x2, x2, x9
	umulh	x3, x10, x7
	madd	x13, x4, x9, x13
	adds	x2, x2, x16
	mul	x4, x12, x10
	cinc	x13, x13, cs  // cs = hs, nlast
	adds	x3, x3, x14
	mul	x14, x6, x5
	cset	x16, cs  // cs = hs, nlast
	mul	x30, x15, x7
	adds	x3, x2, x3
	mul	x17, x11, x8
	adc	x13, x13, x16
	umulh	x2, x12, x15
	adds	x4, x4, x14
	umulh	x16, x5, x10
	cset	x14, cs  // cs = hs, nlast
	umulh	x18, x6, x8
	adds	x17, x17, x30
	cset	x19, cs  // cs = hs, nlast
	adds	x4, x4, x17
	umulh	x30, x11, x7
	adc	x14, x14, x19
	mul	x17, x2, x9
	adds	x18, x16, x18
	umulh	x16, x2, x9
	cset	x2, cs  // cs = hs, nlast
	adds	x4, x4, x18
	umulh	x18, x5, x15
	adc	x14, x14, x2
	adds	x17, x17, x30
	umulh	x2, x12, x11
	cinc	x16, x16, cs  // cs = hs, nlast
	mul	x12, x12, x15
	adds	x4, x4, x17
	adc	x14, x14, x16
	adds	x2, x2, x18
	cset	x16, cs  // cs = hs, nlast
	adds	x2, x2, x12
	cinc	x16, x16, cs  // cs = hs, nlast
	mul	x11, x11, x7
	umulh	x15, x8, x10
	umulh	x12, x2, x9
	mul	x2, x2, x9
	umulh	x7, x6, x7
	madd	x12, x16, x9, x12
	adds	x2, x2, x11
	mul	x6, x6, x8
	mul	x5, x5, x10
	cinc	x12, x12, cs  // cs = hs, nlast
	adds	x7, x15, x7
	cset	x8, cs  // cs = hs, nlast
	adds	x5, x5, x6
	cset	x6, cs  // cs = hs, nlast
	adds	x7, x7, x5
	adc	x5, x8, x6
	adds	x2, x2, x7
	adc	x12, x12, x5
	adds	x1, x1, x3
	cinc	x13, x13, cs  // cs = hs, nlast
	adds	x2, x2, x13
	stp	x1, x2, [x0, #8]
	cinc	x12, x12, cs  // cs = hs, nlast
	adds	x4, x4, x12
	cinc	x14, x14, cs  // cs = hs, nlast
	stp	x4, x14, [x0, #24]
	ldr	x19, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret
	.size secp256k1_fe_mul_44to5, .-secp256k1_fe_mul_44to5

	.p2align 4
	.global secp256k1_fe_sqr_4to5
	.type secp256k1_fe_sqr_4to5, %function
secp256k1_fe_sqr_4to5:
	ldp	x9, x3, [x1]
	mov	x7, #0x3d1                 	// #977
	ldr	x2, [x1, #24]
	movk	x7, #0x1, lsl #32
	ldr	x1, [x1, #16]
	mul	x6, x3, x2
	umulh	x4, x2, x9
	umulh	x5, x3, x1
	adds	x4, x4, x6
	mul	x12, x1, x1
	cset	x6, cs  // cs = hs, nlast
	adds	x5, x4, x5
	cinc	x6, x6, cs  // cs = hs, nlast
	mul	x10, x3, x9
	lsl	x4, x5, #1
	mul	x15, x9, x9
	adds	x4, x4, x12
	extr	x5, x6, x5, #63
	cinc	x5, x5, cs  // cs = hs, nlast
	umulh	x13, x9, x9
	mul	x12, x1, x9
	lsl	x11, x10, #1
	mul	x6, x4, x7
	lsr	x10, x10, #63
	umulh	x4, x4, x7
	madd	x4, x5, x7, x4
	adds	x6, x6, x15
	umulh	x8, x3, x9
	str	x6, [x0]
	cinc	x6, x4, cs  // cs = hs, nlast
	adds	x11, x11, x13
	cinc	x10, x10, cs  // cs = hs, nlast
	adds	x8, x8, x12
	mul	x14, x3, x3
	cset	x12, cs  // cs = hs, nlast
	umulh	x5, x3, x2
	lsl	x13, x8, #1
	mul	x4, x2, x1
	adds	x13, x13, x14
	umulh	x15, x1, x1
	extr	x12, x12, x8, #63
	cinc	x12, x12, cs  // cs = hs, nlast
	adds	x14, x5, x4
	cset	x17, cs  // cs = hs, nlast
	umulh	x8, x2, x1
	lsl	x5, x14, #1
	mul	x18, x2, x2
	adds	x5, x5, x15
	extr	x17, x17, x14, #63
	cinc	x17, x17, cs  // cs = hs, nlast
	lsl	x4, x8, #1
	lsr	x14, x8, #63
	mul	x16, x3, x1
	mul	x15, x5, x7
	umulh	x5, x5, x7
	madd	x5, x17, x7, x5
	adds	x15, x15, x6
	mul	x8, x2, x9
	cinc	x5, x5, cs  // cs = hs, nlast
	adds	x11, x11, x15
	adc	x10, x10, x5
	adds	x4, x4, x18
	cinc	x5, x14, cs  // cs = hs, nlast
	umulh	x9, x1, x9
	umulh	x2, x2, x2
	mul	x6, x4, x7
	umulh	x4, x4, x7
	madd	x4, x5, x7, x4
	adds	x6, x6, x10
	mul	x5, x2, x7
	cinc	x4, x4, cs  // cs = hs, nlast
	adds	x6, x6, x13
	adc	x12, x12, x4
	adds	x4, x8, x16
	cset	x1, cs  // cs = hs, nlast
	adds	x4, x4, x9
	cinc	x1, x1, cs  // cs = hs, nlast
	umulh	x2, x2, x7
	umulh	x3, x3, x3
	lsl	x7, x4, #1
	adds	x7, x7, x12
	extr	x1, x1, x4, #63
	cinc	x1, x1, cs  // cs = hs, nlast
	adds	x3, x5, x3
	cinc	x2, x2, cs  // cs = hs, nlast
	adds	x3, x3, x7
	adc	x1, x1, x2
	stp	x11, x6, [x0, #8]
	stp	x3, x1, [x0, #24]
	ret
	nop
	nop
	.size secp256k1_fe_sqr_4to5, .-secp256k1_fe_sqr_4to5

	.p2align 4
	.global secp256k1_fe_mul_44to4
	.type	secp256k1_fe_mul_44to4, %function
secp256k1_fe_mul_44to4:
	stp	x29, x30, [sp, #-32]!
	mov	x6, #0x3d1                 	// #977
	movk	x6, #0x1, lsl #32
	mov	x29, sp
	ldp	x10, x8, [x1]
	stp	x19, x20, [sp, #16]
	ldp	x13, x15, [x1, #16]
	ldp	x5, x14, [x2, #16]
	ldp	x11, x9, [x2]
	mul	x7, x13, x5
	mul	x3, x8, x14
	umulh	x4, x14, x10
	adds	x1, x3, x7
	mul	x7, x15, x9
	umulh	x2, x8, x5
	cset	x3, cs  // cs = hs, nlast
	adds	x4, x4, x7
	umulh	x7, x13, x9
	cset	x12, cs  // cs = hs, nlast
	adds	x1, x1, x4
	adc	x3, x3, x12
	umulh	x4, x15, x11
	adds	x2, x2, x7
	mul	x7, x10, x11
	cset	x12, cs  // cs = hs, nlast
	adds	x1, x1, x2
	adc	x3, x3, x12
	adds	x1, x1, x4
	cinc	x3, x3, cs  // cs = hs, nlast
	umulh	x4, x13, x5
	umulh	x2, x8, x14
	umulh	x12, x1, x6
	mul	x1, x1, x6
	madd	x12, x3, x6, x12
	mul	x16, x14, x13
	adds	x1, x1, x7
	umulh	x3, x15, x9
	cinc	x12, x12, cs  // cs = hs, nlast
	adds	x2, x2, x4
	mul	x7, x5, x15
	cset	x4, cs  // cs = hs, nlast
	adds	x3, x3, x16
	cset	x16, cs  // cs = hs, nlast
	adds	x2, x2, x3
	adc	x3, x4, x16
	adds	x2, x2, x7
	cinc	x3, x3, cs  // cs = hs, nlast
	mul	x17, x8, x11
	mul	x7, x9, x10
	umulh	x16, x2, x6
	mul	x2, x2, x6
	umulh	x4, x10, x11
	madd	x16, x3, x6, x16
	adds	x2, x2, x17
	mul	x3, x14, x10
	cinc	x16, x16, cs  // cs = hs, nlast
	adds	x4, x4, x7
	mul	x7, x8, x5
	cset	x17, cs  // cs = hs, nlast
	mul	x19, x15, x11
	adds	x4, x2, x4
	mul	x18, x13, x9
	adc	x16, x16, x17
	umulh	x2, x14, x15
	adds	x3, x3, x7
	umulh	x17, x5, x10
	cset	x7, cs  // cs = hs, nlast
	umulh	x30, x8, x9
	adds	x18, x18, x19
	cset	x20, cs  // cs = hs, nlast
	adds	x3, x3, x18
	umulh	x19, x13, x11
	adc	x7, x7, x20
	mul	x18, x2, x6
	adds	x30, x17, x30
	cset	x20, cs  // cs = hs, nlast
	umulh	x17, x2, x6
	adds	x3, x3, x30
	umulh	x2, x14, x13
	umulh	x30, x5, x15
	adc	x7, x7, x20
	adds	x18, x18, x19
	mul	x14, x14, x15
	cinc	x17, x17, cs  // cs = hs, nlast
	adds	x3, x3, x18
	adc	x7, x7, x17
	adds	x2, x2, x30
	cset	x17, cs  // cs = hs, nlast
	adds	x2, x2, x14
	cinc	x17, x17, cs  // cs = hs, nlast
	mul	x13, x13, x11
	umulh	x15, x9, x10
	umulh	x14, x2, x6
	mul	x2, x2, x6
	umulh	x11, x8, x11
	madd	x14, x17, x6, x14
	adds	x2, x2, x13
	mul	x8, x8, x9
	mul	x5, x5, x10
	cinc	x14, x14, cs  // cs = hs, nlast
	adds	x9, x15, x11
	cset	x10, cs  // cs = hs, nlast
	adds	x5, x5, x8
	cset	x8, cs  // cs = hs, nlast
	adds	x9, x9, x5
	adc	x5, x10, x8
	adds	x2, x2, x9
	adc	x14, x14, x5
	adds	x12, x12, x4
	cinc	x16, x16, cs  // cs = hs, nlast
	adds	x2, x2, x16
	cinc	x14, x14, cs  // cs = hs, nlast
	adds	x3, x3, x14
	cinc	x4, x7, cs  // cs = hs, nlast
	ldp	x19, x20, [sp, #16]
	mul	x5, x4, x6
	umulh	x4, x4, x6
	adds	x1, x1, x5
	cinc	x4, x4, cs  // cs = hs, nlast
	adds	x4, x4, x12
	cset	x5, cs  // cs = hs, nlast
	adds	x5, x5, x2
	cset	x2, cs  // cs = hs, nlast
	adds	x2, x2, x3
	stp	x5, x2, [x0, #16]
	cset	x3, cs  // cs = hs, nlast
	ldp	x29, x30, [sp], #32
	mul	x2, x3, x6
	umulh	x3, x3, x6
	adds	x2, x2, x1
	adc	x4, x4, x3
	stp	x2, x4, [x0]
	ret
	.size secp256k1_fe_mul_44to4, .-secp256k1_fe_mul_44to4

	.p2align 4
	.global secp256k1_fe_sqr_4to4
	.type secp256k1_fe_sqr_4to4, %function
secp256k1_fe_sqr_4to4:
	stp	x29, x30, [sp, #-16]!
	mov	x4, #0x3d1                 	// #977
	movk	x4, #0x1, lsl #32
	mov	x29, sp
	ldp	x8, x5, [x1]
	ldr	x3, [x1, #24]
	ldr	x1, [x1, #16]
	mul	x7, x5, x3
	umulh	x2, x3, x8
	umulh	x6, x5, x1
	adds	x2, x2, x7
	mul	x14, x1, x1
	cset	x7, cs  // cs = hs, nlast
	adds	x6, x2, x6
	cinc	x7, x7, cs  // cs = hs, nlast
	mul	x11, x5, x8
	lsl	x2, x6, #1
	mul	x13, x8, x8
	adds	x2, x2, x14
	extr	x6, x7, x6, #63
	cinc	x6, x6, cs  // cs = hs, nlast
	umulh	x12, x8, x8
	mul	x7, x1, x8
	lsl	x9, x11, #1
	umulh	x17, x2, x4
	lsr	x11, x11, #63
	mul	x2, x2, x4
	madd	x17, x6, x4, x17
	adds	x2, x2, x13
	umulh	x10, x5, x8
	cinc	x17, x17, cs  // cs = hs, nlast
	adds	x9, x9, x12
	cinc	x11, x11, cs  // cs = hs, nlast
	adds	x10, x10, x7
	mul	x14, x5, x5
	cset	x12, cs  // cs = hs, nlast
	umulh	x6, x5, x3
	lsl	x13, x10, #1
	mul	x7, x3, x1
	adds	x13, x13, x14
	umulh	x15, x1, x1
	extr	x12, x12, x10, #63
	cinc	x12, x12, cs  // cs = hs, nlast
	adds	x14, x6, x7
	cset	x18, cs  // cs = hs, nlast
	umulh	x10, x3, x1
	lsl	x7, x14, #1
	mul	x30, x3, x3
	adds	x7, x7, x15
	extr	x18, x18, x14, #63
	cinc	x18, x18, cs  // cs = hs, nlast
	lsl	x6, x10, #1
	lsr	x14, x10, #63
	mul	x10, x3, x8
	mul	x15, x7, x4
	umulh	x7, x7, x4
	madd	x7, x18, x4, x7
	adds	x15, x15, x17
	umulh	x17, x1, x8
	cinc	x7, x7, cs  // cs = hs, nlast
	adds	x9, x9, x15
	adc	x11, x11, x7
	adds	x6, x6, x30
	cinc	x7, x14, cs  // cs = hs, nlast
	mul	x16, x5, x1
	umulh	x3, x3, x3
	mul	x8, x6, x4
	umulh	x6, x6, x4
	madd	x6, x7, x4, x6
	adds	x8, x8, x11
	mul	x7, x3, x4
	cinc	x6, x6, cs  // cs = hs, nlast
	adds	x8, x8, x13
	adc	x12, x12, x6
	adds	x6, x10, x16
	cset	x1, cs  // cs = hs, nlast
	adds	x6, x6, x17
	cinc	x1, x1, cs  // cs = hs, nlast
	umulh	x5, x5, x5
	lsl	x10, x6, #1
	umulh	x3, x3, x4
	adds	x10, x10, x12
	extr	x1, x1, x6, #63
	cinc	x1, x1, cs  // cs = hs, nlast
	adds	x5, x7, x5
	cinc	x3, x3, cs  // cs = hs, nlast
	adds	x5, x5, x10
	adc	x1, x1, x3
	ldp	x29, x30, [sp], #16
	mul	x3, x1, x4
	umulh	x1, x1, x4
	adds	x2, x2, x3
	cinc	x1, x1, cs  // cs = hs, nlast
	adds	x1, x1, x9
	cset	x3, cs  // cs = hs, nlast
	adds	x3, x3, x8
	str	x3, [x0, #16]
	cset	x3, cs  // cs = hs, nlast
	adds	x3, x3, x5
	str	x3, [x0, #24]
	cset	x5, cs  // cs = hs, nlast
	mul	x3, x5, x4
	umulh	x5, x5, x4
	adds	x3, x3, x2
	adc	x1, x1, x5
	stp	x3, x1, [x0]
	ret
	.size secp256k1_fe_sqr_4to4, .-secp256k1_fe_sqr_4to4
