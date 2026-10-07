bits 32

global start
extern GetStdHandle
extern WriteFile
extern ExitProcess

section .text
start:
        push    -11
        call    GetStdHandle
        push    0
        push    written
        push    msglen
        push    msg
        push    eax
        call    WriteFile
        push    0
        call    ExitProcess

section .data
msg:    db      'WinPE test 1', 13, 10
msglen  equ     $ - msg

section .bss
written: resd   1
