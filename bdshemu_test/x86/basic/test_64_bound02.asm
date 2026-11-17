    bits 64

    ; Load that ends exactly at the shellcode window end. This is a valid
    ; access and must NOT be misjudged as being outside; emulation continues
    ; until the int3.
    mov rax, 0x200106
    mov rax, [rax]
    int3
