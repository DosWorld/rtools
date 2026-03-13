bits 16
GLOBAL print_msg

SECTION .data
    db 'Z'
msg db 'Hello from external library!$'

SECTION .text
print_msg:
    push ds
    mov  ax, seg msg
    mov  ds, ax
    mov  dx, msg
    mov  ah, 09h
    int  21h
    pop  ds
    retf
    
