    bits 64

    ; Store that straddles the stack window base (starts 4 bytes before the
    ; stack region, writes 8 bytes). Must be rejected with
    ; SHEMU_ABORT_GLA_OUTSIDE (0x1).
    mov rax, 0x1fcffc
    mov [rax], rax
    int3
