    bits 32

    mov     eax, fs:[0x18]
    mov     ebx, eax
    mov     ecx, [ebx+0x30]
    int3
