/************************************************************************
 * Field multiplication and squaring assemblies using representation of *
 * field elements in base 2^{64}.				        *
 * Major instructions used in the assemblies are mul/add/adc.           *
 *									*
 * Copyright (c) 2021 Kaushik Nath                                      *
 * Distributed under the MIT software license, see the accompanying     *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

	.att_syntax
	.text
/*
 * 64-bit field multiplication and squaring using the bottom 4-limbs of 
 * two field elements having 5-limb representation such that the fifth
 * limb is of at most 64 bits. The 5-limb inputs are fully reduced first  
 * to 4-limb forms, then multiplied, after which a field element in 5-limb 
 * form is reported as output. The fifth limb of the output has at most 
 * 33 bits. 
 */
	.p2align 4
	.global secp256k1_fe_mul_55to5
	.type	secp256k1_fe_mul_55to5, %function

secp256k1_fe_mul_55to5:

	movq   %rsp,%r11
	subq   $96,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)
	movq   %rbp,48(%rsp)
	movq   %rdi,56(%rsp)

	movq   $0x1000003d1,%rcx

	movq   0(%rdx),%r8
	movq   8(%rdx),%r9
	movq   16(%rdx),%rbx
	movq   24(%rdx),%rbp
	movq   32(%rdx),%r13

	movq   16(%rsi),%r10
	movq   24(%rsi),%r11
	movq   32(%rsi),%rax

	mulq   %rcx 
	xorq   %rdi,%rdi
	addq   0(%rsi),%rax
	adcq   8(%rsi),%rdx
	adcq   $0,%r10
	movq   %r10,80(%rsp)
	adcq   $0,%r11
	movq   %r11,88(%rsp)
	cmovc  %rcx,%rdi
	addq   %rax,%rdi
	movq   %rdi,64(%rsp)
	adcq   $0,%rdx
	movq   %rdx,72(%rsp)

	movq   %r13,%rax
	mulq   %rcx 
	xorq   %rdi,%rdi
	addq   %r8,%rax
	adcq   %r9,%rdx
	adcq   $0,%rbx
	adcq   $0,%rbp
	cmovc  %rcx,%rdi
	addq   %rax,%rdi
	adcq   $0,%rdx
	movq   %rdx,%rsi

	movq   72(%rsp),%rax
	mulq   %rbp
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11

	movq   80(%rsp),%rax
	mulq   %rbx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   88(%rsp),%rax
	mulq   %rsi
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   80(%rsp),%rax
	mulq   %rbp
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13

	movq   88(%rsp),%rax
	mulq   %rbx
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rcx,%rax
	mulq   %r10
	imul   %rcx,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   88(%rsp),%rax
	mulq   %rbp
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rcx,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rcx,%rax
	mulq   %r12
	imul   %rcx,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   64(%rsp),%rax
	mulq   %rbp
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   72(%rsp),%rax
	mulq   %rbx
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   80(%rsp),%rax
	mulq   %rsi
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   88(%rsp),%rax
	mulq   %rdi
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rcx,%rax
	mulq   %r8
	imul   %rcx,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   64(%rsp),%rax
	mulq   %rdi
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   64(%rsp),%rax
	mulq   %rsi
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   72(%rsp),%rax
	mulq   %rdi
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   64(%rsp),%rax
	mulq   %rbx
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   72(%rsp),%rax
	mulq   %rsi
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   80(%rsp),%rax
	mulq   %rdi
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   56(%rsp),%rdi

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   %r15,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx
	movq   48(%rsp),%rbp

	movq   %r11,%rsp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_5to5
	.type	secp256k1_fe_sqr_5to5, %function

secp256k1_fe_sqr_5to5:

	movq   %rsp,%r11
	subq   $64,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)
	movq   %rbp,48(%rsp)
	movq   %rdi,56(%rsp)

	movq   0(%rsi),%rbx
	movq   8(%rsi),%rbp
	movq   16(%rsi),%rcx
	movq   24(%rsi),%rdi
	movq   32(%rsi),%rax

	movq   $0x1000003d1,%rsi

	mulq   %rsi
	movq   $0,%r8
	addq   %rax,%rbx
	adcq   %rdx,%rbp
	adcq   $0,%rcx
	adcq   $0,%rdi
	cmovc  %rsi,%r8
	addq   %r8,%rbx
	adcq   $0,%rbp

	movq   %rbp,%rax
	mulq   %rdi
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rcx,%rax
	mulq   %rcx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rcx,%rax
	mulq   %rdi
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rsi,%rax
	mulq   %r10
	imul   %rsi,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   %rdi,%rax
	mulq   %rdi
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rsi,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rsi,%rax
	mulq   %r12
	imul   %rsi,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   %rbx,%rax
	mulq   %rdi
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rbp,%rax
	mulq   %rcx
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rsi,%rax
	mulq   %r8
	imul   %rsi,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   %rbx,%rax
	mulq   %rbx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rbx,%rax
	mulq   %rbp
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %rcx
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   %rbp,%rax
	mulq   %rbp
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   56(%rsp),%rdi

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   %r15,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx
	movq   48(%rsp),%rbp

	movq   %r11,%rsp

	ret
/*
 * 64-bit field multiplication and squaring using the bottom 4-limbs of 
 * two field elements having 5-limb representation such that the fifth
 * limb is zero. A field element in 5-limb form is reported as output
 * such that the fifth limb is of at most 33 bits. 
 */
	.p2align 4
	.global secp256k1_fe_mul_44to5
	.type	secp256k1_fe_mul_44to5, %function

secp256k1_fe_mul_44to5:

	movq   %rsp,%r11
	subq   $48,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)

	movq   %rdx,%rcx
	movq   $0x1000003D1,%rbx

	movq   8(%rsi),%rax
	mulq   24(%rcx)
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11

	movq   16(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   24(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   16(%rsi),%rax
	mulq   24(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13

	movq   24(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %r10
	imul   %rbx,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   24(%rsi),%rax
	mulq   24(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rbx,%rax
	mulq   %r12
	imul   %rbx,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   0(%rsi),%rax
	mulq   24(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   8(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   16(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   24(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rbx,%rax
	mulq   %r8
	imul   %rbx,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   0(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   0(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   8(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   0(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   8(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   16(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   %r15,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx

	movq   %r11,%rsp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_4to5
	.type	secp256k1_fe_sqr_4to5, %function

secp256k1_fe_sqr_4to5:

	movq   %rsp,%r11
	subq   $64,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)
	movq   %rbp,48(%rsp)
	movq   %rdi,56(%rsp)

	movq   0(%rsi),%rbx
	movq   8(%rsi),%rbp
	movq   16(%rsi),%rcx
	movq   24(%rsi),%rdi

	movq   $0x1000003D1,%rsi

	movq   %rbp,%rax
	mulq   %rdi
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rcx,%rax
	mulq   %rcx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rcx,%rax
	mulq   %rdi
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rsi,%rax
	mulq   %r10
	imul   %rsi,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   %rdi,%rax
	mulq   %rdi
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rsi,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rsi,%rax
	mulq   %r12
	imul   %rsi,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   %rbx,%rax
	mulq   %rdi
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rbp,%rax
	mulq   %rcx
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rsi,%rax
	mulq   %r8
	imul   %rsi,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   %rbx,%rax
	mulq   %rbx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rbx,%rax
	mulq   %rbp
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %rcx
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   %rbp,%rax
	mulq   %rbp
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   56(%rsp),%rdi

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   %r15,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx
	movq   48(%rsp),%rbp

	movq   %r11,%rsp

	ret
/*
 * 64-bit field multiplication and squaring using the bottom 4-limbs of 
 * two field elements having 5-limb representation such that the fifth
 * limb is zero. A field element in 5-limb form is reported as output
 * such that the fifth limb is zero. 
 */
	.p2align 4
	.global secp256k1_fe_mul_44to4
	.type	secp256k1_fe_mul_44to4, %function

secp256k1_fe_mul_44to4:

	movq   %rsp,%r11
	subq   $48,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)

	movq   %rdx,%rcx
	movq   $0x1000003D1,%rbx

	movq   8(%rsi),%rax
	mulq   24(%rcx)
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11

	movq   16(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   24(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   16(%rsi),%rax
	mulq   24(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13

	movq   24(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %r10
	imul   %rbx,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   24(%rsi),%rax
	mulq   24(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rbx,%rax
	mulq   %r12
	imul   %rbx,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   0(%rsi),%rax
	mulq   24(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   8(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   16(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   24(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rbx,%rax
	mulq   %r8
	imul   %rbx,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   0(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   0(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   8(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   0(%rsi),%rax
	mulq   16(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   8(%rsi),%rax
	mulq   8(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   16(%rsi),%rax
	mulq   0(%rcx)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   %rbx,%rax
	mulq   %r15
	xorq   %r11,%r11
	addq   %rax,%r8
	adcq   %rdx,%r10
	adcq   $0,%r12
	adcq   $0,%r14
	cmovc  %rbx,%r11
	addq   %r11,%r8
	adcq   $0,%r10

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   $0,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx

	movq   %r11,%rsp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_4to4
	.type	secp256k1_fe_sqr_4to4, %function

secp256k1_fe_sqr_4to4:

	movq   %rsp,%r11
	subq   $64,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)
	movq   %rbp,48(%rsp)
	movq   %rdi,56(%rsp)

	movq   0(%rsi),%rbx
	movq   8(%rsi),%rbp
	movq   16(%rsi),%rcx
	movq   24(%rsi),%rdi

	movq   $0x1000003D1,%rsi

	movq   %rbp,%rax
	mulq   %rdi
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rcx,%rax
	mulq   %rcx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rcx,%rax
	mulq   %rdi
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rsi,%rax
	mulq   %r10
	imul   %rsi,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   %rdi,%rax
	mulq   %rdi
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rsi,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rsi,%rax
	mulq   %r12
	imul   %rsi,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   %rbx,%rax
	mulq   %rdi
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rbp,%rax
	mulq   %rcx
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rsi,%rax
	mulq   %r8
	imul   %rsi,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   %rbx,%rax
	mulq   %rbx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   %rbx,%rax
	mulq   %rbp
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rbx,%rax
	mulq   %rcx
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   %rbp,%rax
	mulq   %rbp
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   %rsi,%rax
	mulq   %r15
	xorq   %r11,%r11
	addq   %rax,%r8
	adcq   %rdx,%r10
	adcq   $0,%r12
	adcq   $0,%r14
	cmovc  %rsi,%r11
	addq   %r11,%r8
	adcq   $0,%r10

	movq   56(%rsp),%rdi

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   $0,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx
	movq   48(%rsp),%rbp

	movq   %r11,%rsp

	ret
/*
 * 64-bit field multiplication in which the first argument has 4-limb 
 * and the second argument has 5-limb representations such that the 
 * fifth limb is of at most 64 bits. The second argument is fully 
 * reduced to 4-limb form and then field multiplication is performed. 
 * A field element in 5-limb form is reported as output such that the 
 * fifth limb is of at most 33 bits.
 */
	.p2align 4
	.global secp256k1_fe_mul_45to5
	.type	secp256k1_fe_mul_45to5, %function

secp256k1_fe_mul_45to5:

	movq   %rsp,%r11
	subq   $72,%rsp

	movq   %r11,0(%rsp)
	movq   %r12,8(%rsp)
	movq   %r13,16(%rsp)
	movq   %r14,24(%rsp)
	movq   %r15,32(%rsp)
	movq   %rbx,40(%rsp)
	movq   %rbp,48(%rsp)
	movq   %rdi,56(%rsp)

	movq   $0x1000003d1,%rcx

	movq   0(%rdx),%r8
	movq   8(%rdx),%r9
	movq   16(%rdx),%rbx
	movq   24(%rdx),%rbp
	movq   32(%rdx),%rax

	mulq   %rcx 
	xorq   %rdi,%rdi
	addq   %r8,%rax
	adcq   %r9,%rdx
	adcq   $0,%rbx
	adcq   $0,%rbp
	cmovc  %rcx,%rdi
	addq   %rax,%rdi
	adcq   $0,%rdx
	movq   %rdx,64(%rsp)

	movq   8(%rsi),%rax
	mulq   %rbp
	movq   %rax,%r8
	xorq   %r9,%r9
	movq   %rdx,%r10
	xorq   %r11,%r11

	movq   16(%rsi),%rax
	mulq   %rbx
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   24(%rsi),%rax
	mulq   64(%rsp)
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   16(%rsi),%rax
	mulq   %rbp
	addq   %rax,%r10
	adcq   $0,%r11
	movq   %rdx,%r12
	xorq   %r13,%r13

	movq   24(%rsi),%rax
	mulq   %rbx
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   %rcx,%rax
	mulq   %r10
	imul   %rcx,%r11
	movq   %rax,%r10
	addq   %rdx,%r11

	movq   24(%rsi),%rax
	mulq   %rbp
	addq   %rax,%r12
	adcq   $0,%r13

	movq   %rcx,%rax
	mulq   %rdx
	movq   %rax,%r14
	movq   %rdx,%r15

	movq   %rcx,%rax
	mulq   %r12
	imul   %rcx,%r13
	movq   %rax,%r12
	addq   %rdx,%r13

	movq   0(%rsi),%rax
	mulq   %rbp
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   8(%rsi),%rax
	mulq   %rbx
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   16(%rsi),%rax
	mulq   64(%rsp)
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   24(%rsi),%rax
	mulq   %rdi
	addq   %rax,%r14
	adcq   $0,%r15
	addq   %rdx,%r8
	adcq   $0,%r9

	movq   %rcx,%rax
	mulq   %r8
	imul   %rcx,%r9
	movq   %rax,%r8
	addq   %rdx,%r9

	movq   0(%rsi),%rax
	mulq   %rdi
	addq   %rax,%r8
	adcq   $0,%r9
	addq   %rdx,%r10
	adcq   $0,%r11

	movq   0(%rsi),%rax
	mulq   64(%rsp)
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   8(%rsi),%rax
	mulq   %rdi
	addq   %rax,%r10
	adcq   $0,%r11
	addq   %rdx,%r12
	adcq   $0,%r13

	movq   0(%rsi),%rax
	mulq   %rbx
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   8(%rsi),%rax
	mulq   64(%rsp)
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	movq   16(%rsi),%rax
	mulq   %rdi
	addq   %rax,%r12
	adcq   $0,%r13
	addq   %rdx,%r14
	adcq   $0,%r15

	addq   %r9,%r10
	adcq   $0,%r11
	addq   %r11,%r12
	adcq   $0,%r13
	addq   %r13,%r14
	adcq   $0,%r15

	movq   56(%rsp),%rdi

	movq   %r8,0(%rdi)
	movq   %r10,8(%rdi)
	movq   %r12,16(%rdi)
	movq   %r14,24(%rdi)
	movq   %r15,32(%rdi)

	movq   0(%rsp),%r11
	movq   8(%rsp),%r12
	movq   16(%rsp),%r13
	movq   24(%rsp),%r14
	movq   32(%rsp),%r15
	movq   40(%rsp),%rbx
	movq   48(%rsp),%rbp

	movq   %r11,%rsp

	ret
