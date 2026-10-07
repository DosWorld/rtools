bits 16
global start
extern nothere
section .text
start:
        call    nothere
        ret
