    bits 32

    mov     eax, fs:[0x18]
    xor     eax, eax
    mov     ecx, [eax]
    int3
