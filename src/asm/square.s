.text
.global secp256k1_fe_sqr_inner
secp256k1_fe_sqr_inner: 
	mov    $0x1,%eax
	shlx   %rax,0x10(%rsi),%r10
	mov    0x20(%rsi),%rdx
	mulx   %rdx,%r11,%rcx
	shlx   %rax,(%rsi),%rdx
	mov    $0x34,%r8d
	bzhi   %r8,%r11,%r9
	mov    %rbx,-0x80(%rsp)
	mulx   0x20(%rsi),%rax,%rbx
	mov    %rbp,-0x78(%rsp)
	mov    $0x1,%ebp
	mov    %r12,-0x70(%rsp)
	shlx   %rbp,0x8(%rsi),%r12
	mov    %rdx,%rbp
	mov    0x18(%rsi),%rdx
	mov    %r13,-0x68(%rsp)
	mov    %r14,-0x60(%rsp)
	mulx   %r12,%r13,%r14
	mov    (%rsi),%rdx
	mov    %r15,-0x58(%rsp)
	mulx   %rdx,%r15,%r8
	mov    0x10(%rsi),%rdx
	mov    %rdi,-0x50(%rsp)
	mov    %r8,-0x48(%rsp)
	mulx   %rdx,%rdi,%r8
	adox   %r13,%rdi
	adox   %r8,%r14
	mov    %r12,%rdx
	mulx   0x10(%rsi),%r12,%r13
	add    %rax,%rdi
	adcx   %r14,%rbx
	xchg   %rdx,%rbp
	mulx   0x18(%rsi),%rax,%r8
	xor    %r14,%r14
	adox   %rax,%r12
	adox   %r13,%r8
	movabs $0x1000003d10,%r13
	xchg   %rdx,%r13
	mulx   %r9,%rax,%r14
	shrd   $0x34,%rcx,%r11
	xor    %rcx,%rcx
	adox   %r12,%rax
	adox   %r14,%r8
	mov    %rax,%r9
	shrd   $0x34,%r8,%r9
	test   %al,%al
	adox   %rdi,%r9
	adox   %rcx,%rbx
	mulx   %r11,%rdi,%r12
	mov    0x20(%rsi),%rdx
	mulx   %rbp,%r14,%r11
	adcx   %r9,%rdi
	adcx   %r12,%rbx
	mov    0x18(%rsi),%rdx
	mulx   %r10,%rbp,%r8
	mov    %rdi,%rdx
	shrd   $0x34,%rbx,%rdx
	xor    %r9,%r9
	adox   %r14,%rbp
	adox   %r8,%r11
	adcx   %rbp,%rdx
	adc    $0x0,%r11
	mov    %rdx,%rcx
	mov    0x20(%rsi),%rdx
	mulx   %r10,%r12,%r14
	mov    0x18(%rsi),%rdx
	mulx   %rdx,%r10,%rbx
	movabs $0xfffffffffffff,%rdx
	and    %rdx,%rdi
	adox   %r12,%r10
	adox   %rbx,%r14
	mov    %rcx,%r8
	shrd   $0x34,%r11,%r8
	add    %r10,%r8
	adc    $0x0,%r14
	and    %rdx,%rcx
	shl    $0x4,%rcx
	mov    %r8,%rbp
	shrd   $0x34,%r14,%rbp
	mov    %rdi,%r11
	shr    $0x30,%r11
	lea    (%rcx,%r11,1),%rcx
	mov    %r13,%rdx
	mulx   0x8(%rsi),%r13,%r12
	movabs $0x1000003d1,%rbx
	xchg   %rdx,%rcx
	mulx   %rbx,%r10,%r14
	mov    0x18(%rsi),%r11
	mov    %r11,%rdx
	shl    %rdx
	xor    %r11,%r11
	adox   %r15,%r10
	adox   -0x48(%rsp),%r14
	mulx   0x20(%rsi),%r9,%r15
	movabs $0xfffffffffffff,%rdx
	and    %rdx,%r8
	movabs $0x1000003d10,%r11
	mov    %r11,%rdx
	mulx   %r8,%r11,%rbx
	mov    %r10,%r8
	shrd   $0x34,%r14,%r8
	add    %r13,%r8
	adc    $0x0,%r12
	test   %al,%al
	adox   %r8,%r11
	adox   %rbx,%r12
	mov    %r11,%r13
	shrd   $0x34,%r12,%r13
	test   %al,%al
	adox   %r9,%rbp
	mov    $0x0,%r14d
	adox   %r14,%r15
	movabs $0xfffffffffffff,%r9
	and    %r9,%r11
	mov    %rbp,%rbx
	shrd   $0x34,%r15,%rbx
	mulx   %rbx,%r8,%r12
	and    %r9,%r10
	mov    %rcx,%rdx
	mulx   0x10(%rsi),%rcx,%r15
	mov    -0x50(%rsp),%rdx
	mov    %r10,(%rdx)
	mov    %rdx,%rbx
	mov    0x8(%rsi),%rdx
	mulx   %rdx,%r10,%r14
	adox   %rcx,%r10
	adox   %r14,%r15
	adcx   %r10,%r13
	adc    $0x0,%r15
	and    %r9,%rax
	and    %r9,%rbp
	movabs $0x1000003d10,%rdx
	mulx   %rbp,%rcx,%r14
	adox   %r13,%rcx
	adox   %r14,%r15
	mov    %rcx,%r10
	and    %r9,%r10
	shrd   $0x34,%r15,%rcx
	lea    (%rax,%rcx,1),%rax
	mov    %r10,0x10(%rbx)
	add    %rax,%r8
	adc    $0x0,%r12
	mov    %r8,%r13
	shrd   $0x34,%r12,%r13
	mov    $0x30,%ebp
	bzhi   %rbp,%rdi,%r14
	lea    (%r14,%r13,1),%r14
	mov    %r14,0x20(%rbx)
	and    %r9,%r8
	mov    %r11,0x8(%rbx)
	mov    %r8,0x18(%rbx)
	mov    -0x80(%rsp),%rbx
	mov    -0x78(%rsp),%rbp
	mov    -0x70(%rsp),%r12
	mov    -0x68(%rsp),%r13
	mov    -0x60(%rsp),%r14
	mov    -0x58(%rsp),%r15
	ret    
