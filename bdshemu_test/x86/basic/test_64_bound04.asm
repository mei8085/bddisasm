    bits 64

    ; REP STOSB fully inside the stack region. Must complete normally
    ; (RCX reaches 0), no boundary misjudgment.
    mov rcx, 4
    mov rdi, 0x1fe100
    mov al, 0x41
    rep stosb
    int3
