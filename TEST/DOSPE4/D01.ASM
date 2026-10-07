bits 32

global start
global dlladd

section .text
start:
        mov     eax, 1
        ret     12
dlladd:
        mov     eax, 42
        ret
