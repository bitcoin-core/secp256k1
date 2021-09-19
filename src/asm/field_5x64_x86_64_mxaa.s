/************************************************************************
 * Field multiplication and squaring assemblies using representation of *
 * field elements in base 2^{64}.				        *
 * Major instructions used in the assemblies are mulx/add/adc.          *
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

	movq 	%rsp,%r11
	subq 	$112,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)
	movq 	%rdi,56(%rsp)

	movq    0(%rsi),%r8
	movq    8(%rsi),%r9
	movq    16(%rsi),%r10
	movq    24(%rsi),%r11
	movq    0(%rdx),%r12
	movq    8(%rdx),%r13
	movq    16(%rdx),%rdi
	movq    24(%rdx),%r15
	movq    32(%rdx),%rax

	movq    $0x1000003D1,%rdx
	xorq    %rcx,%rcx
	mulx    32(%rsi),%rbx,%rbp
	addq    %rbx,%r8
	adcq    %rbp,%r9
	adcq    $0,%r10
	adcq    $0,%r11
	cmovc   %rdx,%rcx
	addq    %rcx,%r8
	adcq    $0,%r9

	xorq    %rcx,%rcx
	mulx    %rax,%rax,%rbx
	addq    %rax,%r12
	adcq    %rbx,%r13
	adcq    $0,%rdi
	adcq    $0,%r15
	cmovc   %rdx,%rcx
	addq    %rcx,%r12
	adcq    $0,%r13
	movq    %r15,%rsi

	movq    %r8,64(%rsp)
	movq    %r9,72(%rsp)
	movq    %r10,80(%rsp)
	movq    %r11,88(%rsp)
	movq    %r12,96(%rsp)
	movq    %r13,104(%rsp)

	movq    64(%rsp),%rdx
	mulx    96(%rsp),%r8,%r9
	mulx    104(%rsp),%rcx,%r10
	addq    %rcx,%r9
	mulx    %rdi,%rcx,%r11
	adcq    %rcx,%r10
	mulx    %rsi,%rcx,%r12
	adcq    %rcx,%r11
	adcq    $0,%r12

	movq    72(%rsp),%rdx    
	mulx    96(%rsp),%rax,%rbx
	mulx    104(%rsp),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    %rdi,%rcx,%r15
	adcq    %rcx,%rbp
	mulx    %rsi,%rcx,%r13
	adcq    %rcx,%r15
	adcq    $0,%r13
	addq    %rax,%r9
	adcq    %rbx,%r10
	adcq    %rbp,%r11
	adcq    %r15,%r12
	adcq    $0,%r13

	movq    80(%rsp),%rdx
	mulx    96(%rsp),%rax,%rbx
	mulx    104(%rsp),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    %rdi,%rcx,%r15
	adcq    %rcx,%rbp
	mulx    %rsi,%rcx,%r14
	adcq    %rcx,%r15
	adcq    $0,%r14
	addq    %rax,%r10
	adcq    %rbx,%r11
	adcq    %rbp,%r12
	adcq    %r15,%r13
	adcq    $0,%r14

	movq    88(%rsp),%rdx
	mulx    96(%rsp),%rax,%rbx
	mulx    104(%rsp),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    %rdi,%rcx,%r15
	adcq    %rcx,%rbp
	mulx    %rsi,%rcx,%rsi
	adcq    %rcx,%r15
	adcq    $0,%rsi
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    %rbp,%r13
	adcq    %r15,%r14
	adcq    $0,%rsi

	movq    $0x1000003D1,%rdx
	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13
	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14
	mulx    %rsi,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx
	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	movq 	56(%rsp),%rdi

	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	%rcx,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_5to5
	.type	secp256k1_fe_sqr_5to5, %function

secp256k1_fe_sqr_5to5:

	movq    %rsp,%r11
	subq    $64,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)
	movq 	%rdi,56(%rsp)

	movq    0(%rsi),%rbp
	movq    8(%rsi),%rdi
	movq    16(%rsi),%rcx

	movq    $0x1000003D1,%rdx
	xorq    %r15,%r15
	mulx    32(%rsi),%r13,%r14
	movq    24(%rsi),%rsi
	addq    %r13,%rbp
	adcq    %r14,%rdi
	adcq    $0,%rcx
	adcq    $0,%rsi
	cmovc   %rdx,%r15
	addq    %r15,%rbp
	adcq    $0,%rdi

	movq    %rbp,%rdx    
	mulx    %rdi,%r9,%r10
	mulx    %rcx,%r8,%r11
	addq    %r8,%r10
	mulx    %rsi,%rdx,%r12
	adcq    %rdx,%r11
	adcq    $0,%r12

	movq    %rdi,%rdx
	mulx    %rcx,%rax,%rbx
	mulx    %rsi,%rdx,%r13
	addq    %rdx,%rbx
	adcq    $0,%r13
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    $0,%r13

	movq    %rcx,%rdx
	mulx    %rsi,%rax,%r14
	addq    %rax,%r13
	adcq    $0,%r14

	movq    $0,%r15
	shld    $1,%r14,%r15
	shld    $1,%r13,%r14
	shld    $1,%r12,%r13
	shld    $1,%r11,%r12
	shld    $1,%r10,%r11
	shld    $1,%r9,%r10
	addq    %r9,%r9

	movq    %rbp,%rdx
	mulx    %rdx,%r8,%rax
	addq    %rax,%r9

	movq    %rdi,%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r10
	adcq    %rbx,%r11

	movq    %rcx,%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r12
	adcq    %rbx,%r13

	movq    %rsi,%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r14
	adcq    %rbx,%r15

	movq    $0x1000003D1,%rdx

	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13

	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14

	mulx    %r15,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx

	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	movq 	56(%rsp),%rdi

	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	%rcx,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

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

	movq 	%rsp,%r11
	subq 	$64,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)
	movq 	%rdi,56(%rsp)

	movq    %rdx,%rdi

	movq    0(%rdi),%rdx    
	mulx    0(%rsi),%r8,%r9
	mulx    8(%rsi),%rcx,%r10
	addq    %rcx,%r9
	mulx    16(%rsi),%rcx,%r11
	adcq    %rcx,%r10
	mulx    24(%rsi),%rcx,%r12
	adcq    %rcx,%r11
	adcq    $0,%r12

	movq    8(%rdi),%rdx    
	mulx    0(%rsi),%rax,%rbx
	mulx    8(%rsi),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    16(%rsi),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    24(%rsi),%rcx,%r13
	adcq    %rcx,%r15
	adcq    $0,%r13
	addq    %rax,%r9
	adcq    %rbx,%r10
	adcq    %rbp,%r11
	adcq    %r15,%r12
	adcq    $0,%r13

	movq    16(%rdi),%rdx
	mulx    0(%rsi),%rax,%rbx
	mulx    8(%rsi),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    16(%rsi),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    24(%rsi),%rcx,%r14
	adcq    %rcx,%r15
	adcq    $0,%r14
	addq    %rax,%r10
	adcq    %rbx,%r11
	adcq    %rbp,%r12
	adcq    %r15,%r13
	adcq    $0,%r14

	movq    24(%rdi),%rdx
	mulx    0(%rsi),%rax,%rbx
	mulx    8(%rsi),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    16(%rsi),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    24(%rsi),%rcx,%rsi
	adcq    %rcx,%r15
	adcq    $0,%rsi
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    %rbp,%r13
	adcq    %r15,%r14
	adcq    $0,%rsi

	movq    $0x1000003D1,%rdx
	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13
	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14
	mulx    %rsi,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx
	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	movq 	56(%rsp),%rdi
	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	%rcx,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_4to5
	.type	secp256k1_fe_sqr_4to5, %function

secp256k1_fe_sqr_4to5:

	movq    %rsp,%r11
	subq    $56,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)

	movq    0(%rsi),%rdx    
	mulx    8(%rsi),%r9,%r10
	mulx    16(%rsi),%rcx,%r11
	addq    %rcx,%r10
	mulx    24(%rsi),%rcx,%r12
	adcq    %rcx,%r11
	adcq    $0,%r12

	movq    8(%rsi),%rdx
	mulx    16(%rsi),%rax,%rbx
	mulx    24(%rsi),%rcx,%r13
	addq    %rcx,%rbx
	adcq    $0,%r13
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    $0,%r13

	movq    16(%rsi),%rdx
	mulx    24(%rsi),%rax,%r14
	addq    %rax,%r13
	adcq    $0,%r14

	movq    $0,%r15
	shld    $1,%r14,%r15
	shld    $1,%r13,%r14
	shld    $1,%r12,%r13
	shld    $1,%r11,%r12
	shld    $1,%r10,%r11
	shld    $1,%r9,%r10
	addq    %r9,%r9

	movq    0(%rsi),%rdx
	mulx    %rdx,%r8,%rax
	addq    %rax,%r9

	movq    8(%rsi),%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r10
	adcq    %rbx,%r11

	movq    16(%rsi),%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r12
	adcq    %rbx,%r13

	movq    24(%rsi),%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r14
	adcq    %rbx,%r15

	movq    $0x1000003D1,%rdx
	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13
	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14
	mulx    %r15,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx
	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	%rcx,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

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

	movq 	%rsp,%r11
	subq 	$64,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)
	movq 	%rdi,56(%rsp)

	movq    %rdx,%rdi

	movq    0(%rdi),%rdx    
	mulx    0(%rsi),%r8,%r9
	mulx    8(%rsi),%rcx,%r10
	addq    %rcx,%r9
	mulx    16(%rsi),%rcx,%r11
	adcq    %rcx,%r10
	mulx    24(%rsi),%rcx,%r12
	adcq    %rcx,%r11
	adcq    $0,%r12

	movq    8(%rdi),%rdx    
	mulx    0(%rsi),%rax,%rbx
	mulx    8(%rsi),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    16(%rsi),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    24(%rsi),%rcx,%r13
	adcq    %rcx,%r15
	adcq    $0,%r13
	addq    %rax,%r9
	adcq    %rbx,%r10
	adcq    %rbp,%r11
	adcq    %r15,%r12
	adcq    $0,%r13

	movq    16(%rdi),%rdx
	mulx    0(%rsi),%rax,%rbx
	mulx    8(%rsi),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    16(%rsi),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    24(%rsi),%rcx,%r14
	adcq    %rcx,%r15
	adcq    $0,%r14
	addq    %rax,%r10
	adcq    %rbx,%r11
	adcq    %rbp,%r12
	adcq    %r15,%r13
	adcq    $0,%r14

	movq    24(%rdi),%rdx
	mulx    0(%rsi),%rax,%rbx
	mulx    8(%rsi),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    16(%rsi),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    24(%rsi),%rcx,%rsi
	adcq    %rcx,%r15
	adcq    $0,%rsi
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    %rbp,%r13
	adcq    %r15,%r14
	adcq    $0,%rsi

	movq    $0x1000003D1,%rdx
	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13
	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14
	mulx    %rsi,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx
	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	xorq    %r15,%r15
	mulx    %rcx,%r13,%r14
	addq    %r13,%r8
	adcq    %r14,%r9
	adcq    $0,%r10
	adcq    $0,%r11
	cmovc   %rdx,%r15
	addq    %r15,%r8
	adcq    $0,%r9

	movq 	56(%rsp),%rdi

	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	$0,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_4to4
	.type	secp256k1_fe_sqr_4to4, %function

secp256k1_fe_sqr_4to4:

	movq    %rsp,%r11
	subq    $56,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)

	movq    0(%rsi),%rdx    
	mulx    8(%rsi),%r9,%r10
	mulx    16(%rsi),%rcx,%r11
	addq    %rcx,%r10
	mulx    24(%rsi),%rcx,%r12
	adcq    %rcx,%r11
	adcq    $0,%r12

	movq    8(%rsi),%rdx
	mulx    16(%rsi),%rax,%rbx
	mulx    24(%rsi),%rcx,%r13
	addq    %rcx,%rbx
	adcq    $0,%r13
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    $0,%r13

	movq    16(%rsi),%rdx
	mulx    24(%rsi),%rax,%r14
	addq    %rax,%r13
	adcq    $0,%r14

	movq    $0,%r15
	shld    $1,%r14,%r15
	shld    $1,%r13,%r14
	shld    $1,%r12,%r13
	shld    $1,%r11,%r12
	shld    $1,%r10,%r11
	shld    $1,%r9,%r10
	addq    %r9,%r9

	movq    0(%rsi),%rdx
	mulx    %rdx,%r8,%rax
	addq    %rax,%r9

	movq    8(%rsi),%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r10
	adcq    %rbx,%r11

	movq    16(%rsi),%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r12
	adcq    %rbx,%r13

	movq    24(%rsi),%rdx
	mulx    %rdx,%rax,%rbx
	adcq    %rax,%r14
	adcq    %rbx,%r15

	movq    $0x1000003D1,%rdx
	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13
	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14
	mulx    %r15,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx
	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	xorq    %r15,%r15
	mulx    %rcx,%r13,%r14
	addq    %r13,%r8
	adcq    %r14,%r9
	adcq    $0,%r10
	adcq    $0,%r11
	cmovc   %rdx,%r15
	addq    %r15,%r8
	adcq    $0,%r9

	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	$0,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

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

	movq 	%rsp,%r11
	subq 	$88,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)

	movq    0(%rdx),%r12
	movq    8(%rdx),%r13
	movq    16(%rdx),%r14
	movq    24(%rdx),%r15
	movq    32(%rdx),%rax

	movq    $0x1000003D1,%rdx
	xorq    %rcx,%rcx
	mulx    %rax,%rax,%rbx
	addq    %rax,%r12
	adcq    %rbx,%r13
	adcq    $0,%r14
	adcq    $0,%r15
	cmovc   %rdx,%rcx
	addq    %rcx,%r12
	adcq    $0,%r13

	movq    %r12,56(%rsp)
	movq    %r13,64(%rsp)
	movq    %r14,72(%rsp)
	movq    %r15,80(%rsp)

	movq    0(%rsi),%rdx
	mulx    56(%rsp),%r8,%r9
	mulx    64(%rsp),%rcx,%r10
	addq    %rcx,%r9
	mulx    72(%rsp),%rcx,%r11
	adcq    %rcx,%r10
	mulx    80(%rsp),%rcx,%r12
	adcq    %rcx,%r11
	adcq    $0,%r12

	movq    8(%rsi),%rdx    
	mulx    56(%rsp),%rax,%rbx
	mulx    64(%rsp),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    72(%rsp),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    80(%rsp),%rcx,%r13
	adcq    %rcx,%r15
	adcq    $0,%r13
	addq    %rax,%r9
	adcq    %rbx,%r10
	adcq    %rbp,%r11
	adcq    %r15,%r12
	adcq    $0,%r13

	movq    16(%rsi),%rdx
	mulx    56(%rsp),%rax,%rbx
	mulx    64(%rsp),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    72(%rsp),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    80(%rsp),%rcx,%r14
	adcq    %rcx,%r15
	adcq    $0,%r14
	addq    %rax,%r10
	adcq    %rbx,%r11
	adcq    %rbp,%r12
	adcq    %r15,%r13
	adcq    $0,%r14

	movq    24(%rsi),%rdx
	mulx    56(%rsp),%rax,%rbx
	mulx    64(%rsp),%rcx,%rbp
	addq    %rcx,%rbx
	mulx    72(%rsp),%rcx,%r15
	adcq    %rcx,%rbp
	mulx    80(%rsp),%rcx,%rsi
	adcq    %rcx,%r15
	adcq    $0,%rsi
	addq    %rax,%r11
	adcq    %rbx,%r12
	adcq    %rbp,%r13
	adcq    %r15,%r14
	adcq    $0,%rsi

	movq    $0x1000003D1,%rdx
	mulx    %r12,%r12,%rbx
	mulx    %r13,%r13,%rcx
	addq    %rbx,%r13
	mulx    %r14,%r14,%rbx
	adcq    %rcx,%r14
	mulx    %rsi,%r15,%rcx
	adcq    %rbx,%r15
	adcq    $0,%rcx
	addq    %r12,%r8
	adcq    %r13,%r9
	adcq    %r14,%r10
	adcq    %r15,%r11
	adcq    $0,%rcx

	movq   	%r8,0(%rdi)
	movq   	%r9,8(%rdi)
	movq   	%r10,16(%rdi)
	movq   	%r11,24(%rdi)
	movq   	%rcx,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

	ret
