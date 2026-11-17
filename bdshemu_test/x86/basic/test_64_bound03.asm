    bits 64

    ; REP MOVSQ copying from the shellcode to the stack. The second iteration
    ; straddles the stack window top, so the emulation must stop with
    ; SHEMU_ABORT_GLA_OUTSIDE (0x1), and RCX/RSI/RDI must reflect only the
    ; completed (first) iteration.
    mov rcx, 5
    mov rsi, 0x200100
    mov rdi, 0x1feff4
    rep movsq
    int3
