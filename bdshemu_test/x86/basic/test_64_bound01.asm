    bits 64

    ; Load that straddles the shellcode window end (starts 4 bytes before the
    ; end of the shellcode region, reads 8 bytes). Must be rejected with
    ; SHEMU_ABORT_GLA_OUTSIDE (0x1) - accesses are isolated per region.
    mov rax, 0x20010a
    mov rax, [rax]
    int3
