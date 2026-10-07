bits 32

global start
extern FindResourceA
extern SizeofResource
extern ExitProcess

section .text
start:
        push    10
        push    1
        push    0
        call    FindResourceA
        or      eax, eax
        jz      bad
        push    eax
        push    0
        call    SizeofResource
        cmp     eax, 5
        jne     bad
        push    0
        call    ExitProcess
bad:
        push    1
        call    ExitProcess
