    bits 64

    ; Store that ends exactly at the stack window top. This is a valid
    ; access and must NOT be misjudged; emulation continues until the int3.
    mov rax, 0x1feff8
    mov [rax], rax
    int3
