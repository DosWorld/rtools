bits 32

global start
global hello
global answer
extern GetStdHandle
extern WriteFile

section .text
start:
        mov     eax, 1
        ret     12
hello:
        push    -11
        call    GetStdHandle
        push    0
        push    written
        push    msglen
        push    msg
        push    eax
        call    WriteFile
        ret
answer:
        mov     eax, 42
        ret

section .data
msg:    db      'WinPE dll hello', 13, 10
msglen  equ     $ - msg

section .bss
written: resd   1
