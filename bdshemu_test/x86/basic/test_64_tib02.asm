    bits 64

    mov     rax, gs:[0x30]
    mov     rbx, rax
    mov     ecx, [rbx+0x60]
    int3
