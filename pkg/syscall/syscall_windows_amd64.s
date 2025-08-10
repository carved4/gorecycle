
#include "go_asm.h"
#include "textflag.h"
#define maxargs 16
// func getTrampoline(stubAddr uintptr) uintptr
TEXT ·getTrampoline(SB),NOSPLIT,$0-8
    MOVQ stubAddr+0(FP), AX
    MOVQ AX, R10
    NOP
    NOP
    ADDQ $29, AX
    NOP
loop:
    XORQ DI, DI
    NOP
    // check for 0x0f05c3 byte sequence
    MOVB $0x0f, DI
    CMPB DI, 0(AX)
    JNE nope
    NOP
    MOVB $0x05, DI
    CMPB DI, 1(AX)
    JNE nope
    NOP
    MOVB $0xc3, DI
    CMPB DI, 2(AX)
    JNE nope
    NOP
    MOVQ AX, ret+8(FP)
    RET
    NOP
nope:
    CMPQ AX, R10
    JE not_found
    NOP
    DECQ AX
    JMP loop

not_found:
    NOP
    XORQ AX, AX
    MOVQ AX, ret+8(FP)
    RET

TEXT ·do_syscall_indirect(SB),NOSPLIT,$0-40
    XORQ    AX, AX
    MOVW    ssn+0(FP), AX
	NOP
    XORQ    R11, R11
    MOVQ    trampoline+8(FP), R11
	NOP
    PUSHQ   CX
	NOP 
    MOVQ    argh_base+16(FP),SI
    NOP
    MOVQ    argh_len+24(FP),CX
    NOP
    MOVQ    0x30(GS), DI
    MOVL    $0, 0x68(DI)
    SUBQ    $(maxargs*8), SP	
    CMPL    CX, $0
    JLE     jumpcall
    CMPL    CX, $4
    JLE	    loadregs
    CMPL    CX, $maxargs
    JLE	    2(PC)
    INT	    $3			
    MOVQ    SP, DI
    CLD
    REP; MOVSQ
    MOVQ    SP, SI
	
loadregs:
    MOVQ	0(SI), CX
    MOVQ	8(SI), DX
    MOVQ	16(SI), R8
    MOVQ	24(SI), R9
    MOVQ	CX, X0
    MOVQ	DX, X1
    MOVQ	R8, X2
    MOVQ	R9, X3
	
jumpcall:
    MOVQ    CX, R10
    CALL    R11
    ADDQ	$((maxargs)*8), SP
    // Return result
    POPQ	CX
    MOVL	AX, errcode+40(FP)
    RET

