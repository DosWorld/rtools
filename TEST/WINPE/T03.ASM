bits 32

global start
extern hello
extern answer
extern ansord
extern ExitProcess

section .text
start:
        call    hello
        call    answer
        cmp     eax, 42
        jne     bad
        call    ansord
        cmp     eax, 42
        jne     bad
        push    0
        call    ExitProcess
bad:
        push    1
        call    ExitProcess
