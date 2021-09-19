/************************************************************************
 * Field multiplication and squaring assemblies using representation of *
 * field elements in base 2^{64}.				        *
 * Major instructions used in the assemblies are mulx/adcx/adox.        *
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
	subq 	$96,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)
	movq 	%rdi,56(%rsp)

	movq    0(%rsi),%rax
	movq    8(%rsi),%rbx
	movq    16(%rsi),%rdi

	movq    0(%rdx),%r8
	movq    8(%rdx),%r9
	movq    16(%rdx),%r10
	movq    24(%rdx),%r11
	movq    32(%rdx),%r12

	movq    $0x1000003D1,%rdx
	xorq    %rcx,%rcx
	mulx    32(%rsi),%r13,%r14
	movq    24(%rsi),%rsi
	adcx    %r13,%rax
	adcx    %r14,%rbx
	adcx    %rcx,%rdi
	adcx    %rcx,%rsi
	cmovc   %rdx,%rcx
	xorq    %r13,%r13
	adcx    %rcx,%rax
	adcx    %r13,%rbx

	xorq    %rcx,%rcx
	mulx    %r12,%r13,%r14
	adcx    %r13,%r8
	adcx    %r14,%r9
	adcx    %rcx,%r10
	adcx    %rcx,%r11
	cmovc   %rdx,%rcx
	xorq    %r13,%r13
	adcx    %rcx,%r8
	adcx    %r13,%r9

	movq    %r8,64(%rsp)
	movq    %r9,72(%rsp)
	movq    %r10,80(%rsp)
	movq    %r11,88(%rsp)

	xorq    %r13,%r13
	movq    64(%rsp),%rdx    
	mulx    %rax,%r8,%r9
	mulx    %rbx,%rcx,%r10
	adcx    %rcx,%r9     
	mulx    %rdi,%rcx,%r11
	adcx    %rcx,%r10    
	mulx    %rsi,%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    72(%rsp),%rdx
	mulx    %rax,%rcx,%rbp
	adcx    %rcx,%r9
	adox    %rbp,%r10
	mulx    %rbx,%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    %rdi,%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    %rsi,%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13	
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    80(%rsp),%rdx
	mulx    %rax,%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    %rbx,%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    %rdi,%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    %rsi,%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	adcx    %r15,%r14

	xorq    %rdx,%rdx
	movq    88(%rsp),%rdx
	mulx    %rax,%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    %rbx,%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    %rdi,%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	mulx    %rsi,%rcx,%rbp
	adcx    %rcx,%r14
	adox    %rbp,%r15			
	adcq    $0,%r15
	  
	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%r12 
	adcx    %rax,%r8
	adox    %r12,%r9
	mulx    %r13,%rcx,%r13
	adcx    %rcx,%r9
	adox    %r13,%r10
	mulx    %r14,%rcx,%r14
	adcx    %rcx,%r10
	adox    %r14,%r11
	mulx    %r15,%rcx,%r15
	adcx    %rcx,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15

	movq    56(%rsp),%rdi

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    %r15,32(%rdi)

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
	subq    $56,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)

	movq    0(%rsi),%rbx  
	movq    8(%rsi),%rbp  
	movq    16(%rsi),%rax

	movq    $0x1000003D1,%rdx
	xorq    %r15,%r15
	mulx    32(%rsi),%r13,%r14
	movq    24(%rsi),%rsi
	adcx    %r13,%rbx
	adcx    %r14,%rbp
	adcx    %r15,%rax
	adcx    %r15,%rsi
	cmovc   %rdx,%r15
	xorq    %r13,%r13
	adcx    %r15,%rbx
	adcx    %r13,%rbp

	xorq    %r13,%r13
	movq    %rbx,%rdx
	mulx    %rbp,%r9,%r10
	mulx    %rax,%rcx,%r11
	adcx    %rcx,%r10
	mulx    %rsi,%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    %rbp,%rdx
	mulx    %rax,%rcx,%rdx
	adcx    %rcx,%r11
	adox    %rdx,%r12
	movq    %rbp,%rdx
	mulx    %rsi,%rcx,%rdx
	adcx    %rcx,%r12
	adox    %rdx,%r13
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    %rax,%rdx
	mulx    %rsi,%rcx,%r14
	adcx    %rcx,%r13
	adcx    %r15,%r14

	shld    $1,%r14,%r15
	shld    $1,%r13,%r14
	shld    $1,%r12,%r13
	shld    $1,%r11,%r12
	shld    $1,%r10,%r11
	shld    $1,%r9,%r10
	addq    %r9,%r9
	     
	xorq    %rdx,%rdx
	movq    %rbx,%rdx
	mulx    %rdx,%r8,%rdx
	adcx    %rdx,%r9

	movq    %rbp,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r10
	adcx    %rdx,%r11

	movq    %rax,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r12
	adcx    %rdx,%r13

	movq    %rsi,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r14
	adcx    %rdx,%r15	

	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%r12 
	adcx    %rax,%r8
	adox    %r12,%r9
	mulx    %r13,%rcx,%r13
	adcx    %rcx,%r9
	adox    %r13,%r10
	mulx    %r14,%rcx,%r14
	adcx    %rcx,%r10
	adox    %r14,%r11
	mulx    %r15,%rcx,%r15
	adcx    %rcx,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15	

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    %r15,32(%rdi)

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

	push    %rbp
	push    %rbx
	push    %r12
	push    %r13
	push    %r14
	push    %r15
	    
	movq    %rdx,%rbx

	xorq    %r13,%r13    
	movq    0(%rbx),%rdx    
	mulx    0(%rsi),%r8,%r9
	mulx    8(%rsi),%rcx,%r10
	adcx    %rcx,%r9     
	mulx    16(%rsi),%rcx,%r11
	adcx    %rcx,%r10    
	mulx    24(%rsi),%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    8(%rbx),%rdx
	mulx    0(%rsi),%rcx,%rbp
	adcx    %rcx,%r9
	adox    %rbp,%r10
	mulx    8(%rsi),%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    16(%rsi),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    24(%rsi),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13	
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    16(%rbx),%rdx
	mulx    0(%rsi),%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    8(%rsi),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    16(%rsi),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    24(%rsi),%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	adcx    %r15,%r14

	xorq    %rax,%rax
	movq    24(%rbx),%rdx
	mulx    0(%rsi),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    8(%rsi),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    16(%rsi),%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	mulx    24(%rsi),%rcx,%rbp
	adcx    %rcx,%r14
	adox    %rbp,%r15			
	adcx    %rax,%r15
	  
	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%r12 
	adcx    %rax,%r8
	adox    %r12,%r9
	mulx    %r13,%rcx,%r13
	adcx    %rcx,%r9
	adox    %r13,%r10
	mulx    %r14,%rcx,%r14
	adcx    %rcx,%r10
	adox    %r14,%r11
	mulx    %r15,%rcx,%r15
	adcx    %rcx,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    %r15,32(%rdi)

	pop     %r15
	pop     %r14
	pop     %r13
	pop     %r12
	pop     %rbx
	pop     %rbp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_4to5
	.type	secp256k1_fe_sqr_4to5, %function

secp256k1_fe_sqr_4to5:

	push    %rbp
	push    %rbx
	push    %r12
	push    %r13
	push    %r14
	push    %r15

	movq    0(%rsi),%rbx  
	movq    8(%rsi),%rbp  
	movq    16(%rsi),%rax
	movq    24(%rsi),%rsi

	xorq    %r13,%r13
	movq    %rbx,%rdx
	mulx    %rbp,%r9,%r10
	mulx    %rax,%rcx,%r11
	adcx    %rcx,%r10
	mulx    %rsi,%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    %rbp,%rdx
	mulx    %rax,%rcx,%rdx
	adcx    %rcx,%r11
	adox    %rdx,%r12
	movq    %rbp,%rdx
	mulx    %rsi,%rcx,%rdx
	adcx    %rcx,%r12
	adox    %rdx,%r13
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    %rax,%rdx
	mulx    %rsi,%rcx,%r14
	adcx    %rcx,%r13
	adcx    %r15,%r14

	shld    $1,%r14,%r15
	shld    $1,%r13,%r14
	shld    $1,%r12,%r13
	shld    $1,%r11,%r12
	shld    $1,%r10,%r11
	shld    $1,%r9,%r10
	addq    %r9,%r9
	     
	xorq    %rdx,%rdx
	movq    %rbx,%rdx
	mulx    %rdx,%r8,%rdx
	adcx    %rdx,%r9

	movq    %rbp,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r10
	adcx    %rdx,%r11

	movq    %rax,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r12
	adcx    %rdx,%r13

	movq    %rsi,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r14
	adcx    %rdx,%r15

	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%rbx
	adcx    %rax,%r8
	adox    %rbx,%r9
	mulx    %r13,%rax,%rbx
	adcx    %rax,%r9
	adox    %rbx,%r10
	mulx    %r14,%rax,%rbx
	adcx    %rax,%r10
	adox    %rbx,%r11
	mulx    %r15,%rax,%r15
	adcx    %rax,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    %r15,32(%rdi)

	pop     %r15
	pop     %r14
	pop     %r13
	pop     %r12
	pop     %rbx
	pop     %rbp

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

	push    %rbp
	push    %rbx
	push    %r12
	push    %r13
	push    %r14
	push    %r15
	    
	movq    %rdx,%rbx

	xorq    %r13,%r13    
	movq    0(%rbx),%rdx    
	mulx    0(%rsi),%r8,%r9
	mulx    8(%rsi),%rcx,%r10
	adcx    %rcx,%r9     
	mulx    16(%rsi),%rcx,%r11
	adcx    %rcx,%r10    
	mulx    24(%rsi),%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    8(%rbx),%rdx
	mulx    0(%rsi),%rcx,%rbp
	adcx    %rcx,%r9
	adox    %rbp,%r10
	mulx    8(%rsi),%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    16(%rsi),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    24(%rsi),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13	
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    16(%rbx),%rdx
	mulx    0(%rsi),%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    8(%rsi),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    16(%rsi),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    24(%rsi),%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	adcx    %r15,%r14

	xorq    %rax,%rax
	movq    24(%rbx),%rdx
	mulx    0(%rsi),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    8(%rsi),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    16(%rsi),%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	mulx    24(%rsi),%rcx,%rbp
	adcx    %rcx,%r14
	adox    %rbp,%r15			
	adcx    %rax,%r15
	  
	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%r12 
	adcx    %rax,%r8
	adox    %r12,%r9
	mulx    %r13,%rcx,%r13
	adcx    %rcx,%r9
	adox    %r13,%r10
	mulx    %r14,%rcx,%r14
	adcx    %rcx,%r10
	adox    %r14,%r11
	mulx    %r15,%rcx,%r15
	adcx    %rcx,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15

	xorq    %rbp,%rbp
	mulx    %r15,%r14,%r15
	adcx    %r14,%r8	
	adcx    %r15,%r9
	adcx    %rbp,%r10
	adcx    %rbp,%r11
	cmovc   %rdx,%rbp
	xorq    %rbx,%rbx
	adcx    %rbp,%r8
	adcx    %rbx,%r9

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    $0,32(%rdi)

	pop     %r15
	pop     %r14
	pop     %r13
	pop     %r12
	pop     %rbx
	pop     %rbp

	ret


	.p2align 4
	.global secp256k1_fe_sqr_4to4
	.type	secp256k1_fe_sqr_4to4, %function

secp256k1_fe_sqr_4to4:

	push    %rbp
	push    %rbx
	push    %r12
	push    %r13
	push    %r14
	push    %r15

	movq    0(%rsi),%rbx  
	movq    8(%rsi),%rbp  
	movq    16(%rsi),%rax
	movq    24(%rsi),%rsi

	xorq    %r13,%r13
	movq    %rbx,%rdx
	mulx    %rbp,%r9,%r10
	mulx    %rax,%rcx,%r11
	adcx    %rcx,%r10
	mulx    %rsi,%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    %rbp,%rdx
	mulx    %rax,%rcx,%rdx
	adcx    %rcx,%r11
	adox    %rdx,%r12
	movq    %rbp,%rdx
	mulx    %rsi,%rcx,%rdx
	adcx    %rcx,%r12
	adox    %rdx,%r13
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    %rax,%rdx
	mulx    %rsi,%rcx,%r14
	adcx    %rcx,%r13
	adcx    %r15,%r14

	shld    $1,%r14,%r15
	shld    $1,%r13,%r14
	shld    $1,%r12,%r13
	shld    $1,%r11,%r12
	shld    $1,%r10,%r11
	shld    $1,%r9,%r10
	addq    %r9,%r9
	     
	xorq    %rdx,%rdx
	movq    %rbx,%rdx
	mulx    %rdx,%r8,%rdx
	adcx    %rdx,%r9

	movq    %rbp,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r10
	adcx    %rdx,%r11

	movq    %rax,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r12
	adcx    %rdx,%r13

	movq    %rsi,%rdx
	mulx    %rdx,%rcx,%rdx
	adcx    %rcx,%r14
	adcx    %rdx,%r15

	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%rbx
	adcx    %rax,%r8
	adox    %rbx,%r9
	mulx    %r13,%rax,%rbx
	adcx    %rax,%r9
	adox    %rbx,%r10
	mulx    %r14,%rax,%rbx
	adcx    %rax,%r10
	adox    %rbx,%r11
	mulx    %r15,%rax,%r15
	adcx    %rax,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15

	xorq    %rbp,%rbp
	mulx    %r15,%r14,%r15
	adcx    %r14,%r8	
	adcx    %r15,%r9
	adcx    %rbp,%r10
	adcx    %rbp,%r11
	cmovc   %rdx,%rbp
	xorq    %rbx,%rbx
	adcx    %rbp,%r8
	adcx    %rbx,%r9

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    $0,32(%rdi)

	pop     %r15
	pop     %r14
	pop     %r13
	pop     %r12
	pop     %rbx
	pop     %rbp

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
	subq 	$72,%rsp

	movq 	%r11,0(%rsp)
	movq 	%r12,8(%rsp)
	movq 	%r13,16(%rsp)
	movq 	%r14,24(%rsp)
	movq 	%r15,32(%rsp)
	movq 	%rbp,40(%rsp)
	movq 	%rbx,48(%rsp)
	movq 	%rdi,56(%rsp)

	movq    0(%rdx),%rax
	movq    8(%rdx),%rbx
	movq    16(%rdx),%r8
	movq    24(%rdx),%rdi

	movq    %rdx,%r15
	movq    $0x1000003D1,%rdx
	xorq    %rcx,%rcx
	mulx    32(%r15),%r13,%r14
	adcx    %r13,%rax
	adcx    %r14,%rbx
	adcx    %rcx,%r8
	adcx    %rcx,%rdi
	cmovc   %rdx,%rcx
	xorq    %r13,%r13
	adcx    %rcx,%rax
	adcx    %r13,%rbx
	movq    %r8,64(%rsp)

	xorq    %r13,%r13
	movq    0(%rsi),%rdx    
	mulx    %rax,%r8,%r9
	mulx    %rbx,%rcx,%r10
	adcx    %rcx,%r9     
	mulx    64(%rsp),%rcx,%r11
	adcx    %rcx,%r10    
	mulx    %rdi,%rcx,%r12
	adcx    %rcx,%r11
	adcx    %r13,%r12

	xorq    %r14,%r14
	movq    8(%rsi),%rdx
	mulx    %rax,%rcx,%rbp
	adcx    %rcx,%r9
	adox    %rbp,%r10
	mulx    %rbx,%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    64(%rsp),%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    %rdi,%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13	
	adcx    %r14,%r13

	xorq    %r15,%r15
	movq    16(%rsi),%rdx
	mulx    %rax,%rcx,%rbp
	adcx    %rcx,%r10
	adox    %rbp,%r11
	mulx    %rbx,%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    64(%rsp),%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    %rdi,%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	adcx    %r15,%r14

	xorq    %rdx,%rdx
	movq    24(%rsi),%rdx
	mulx    %rax,%rcx,%rbp
	adcx    %rcx,%r11
	adox    %rbp,%r12
	mulx    %rbx,%rcx,%rbp
	adcx    %rcx,%r12
	adox    %rbp,%r13
	mulx    64(%rsp),%rcx,%rbp
	adcx    %rcx,%r13
	adox    %rbp,%r14
	mulx    %rdi,%rcx,%rbp
	adcx    %rcx,%r14
	adox    %rbp,%r15			
	adcq    $0,%r15
	  
	xorq    %rbp,%rbp
	movq    $0x1000003D1,%rdx
	mulx    %r12,%rax,%r12 
	adcx    %rax,%r8
	adox    %r12,%r9
	mulx    %r13,%rcx,%r13
	adcx    %rcx,%r9
	adox    %r13,%r10
	mulx    %r14,%rcx,%r14
	adcx    %rcx,%r10
	adox    %r14,%r11
	mulx    %r15,%rcx,%r15
	adcx    %rcx,%r11
	adox    %rbp,%r15
	adcx    %rbp,%r15

	movq    56(%rsp),%rdi

	movq    %r8,0(%rdi)
	movq    %r9,8(%rdi)
	movq    %r10,16(%rdi)
	movq    %r11,24(%rdi)
	movq    %r15,32(%rdi)

	movq 	 0(%rsp),%r11
	movq 	 8(%rsp),%r12
	movq 	16(%rsp),%r13
	movq 	24(%rsp),%r14
	movq 	32(%rsp),%r15
	movq 	40(%rsp),%rbp
	movq 	48(%rsp),%rbx

	movq 	%r11,%rsp

	ret
