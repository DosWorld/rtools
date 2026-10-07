bits 32

global start
extern fhello
extern fans
extern ExitProcess

section .text
start:
        call    fhello
        call    fans
        cmp     eax, 42
        jne     bad
        push    0
        call    ExitProcess
bad:
        push    1
        call    ExitProcess
