;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

extern __oe_dispatch_ocall:proc

;;==============================================================================
;;
;; void oe_enter(
;;     [IN] void* tcs,
;;     [IN] void (*aep)(),
;;     [IN] uint64_t arg1,
;;     [IN] uint64_t arg2,
;;     [OUT] uint64_t* arg3,
;;     [OUT] uint64_t* arg4,
;;     [OUT] oe_enclave_t* enclave);
;;
;; Registers:
;;     RCX      - tcs: thread control structure (extended)
;;     RDX      - aep: asynchronous execution procedure
;;     R8       - arg1
;;     R9       - arg2
;;     [RBP+48] - arg3
;;     [RBP+56] - arg4
;;
;; These registers may be destroyed across function calls:
;;     RAX, RCX, RDX, R8, R9, R10, R11
;;
;; These registers must be preserved across function calls:
;;     RBX, RBP, RDI, RSI, RSP, R12, R13, R14, and R15
;;
;;==============================================================================

ENCLU_EENTER    EQU 2
PARAMS_SPACE    EQU 128
TCS             EQU [rbp-8]
AEP             EQU [rbp-16]
ARG1            EQU [rbp-24]
ARG2            EQU [rbp-32]
ARG3            EQU [rbp-40]
ARG4            EQU [rbp-48]
ENCLAVE         EQU [rbp-56]
ARG1OUT         EQU [rbp-64]
ARG2OUT         EQU [rbp-72]
STACKPTR        EQU [rbp-80]
MXCSR           EQU [rbp-88]

NESTED_ENTRY oe_enter, _TEXT$00
    END_PROLOGUE

    ;; Setup stack frame:
    push rbp
    mov rbp, rsp

    ;; Save parameters on stack for later reference:
    ;;     TCS  := [RBP-8]  <- RCX
    ;;     AEP  := [RBP-16] <- RDX
    ;;     ARG1 := [RBP-24] <- R8
    ;;     ARG2 := [RBP-32] <- R9
    ;;     ARG3 := [RBP-40] <- [RBP+48]
    ;;     ARG4 := [RBP-48] <- [RBP+56]
    ;;     ENCLAVE := [RBP-56] <- [RBP+64]
    ;;     MXCSR := [RBP-88]
    sub rsp, PARAMS_SPACE
    mov TCS, rcx
    mov AEP, rdx
    mov ARG1, r8
    mov ARG2, r9
    mov rax, [rbp+48]
    mov ARG3, rax
    mov rax, [rbp+56]
    mov ARG4, rax
    mov rax, [rbp+64]
    mov ENCLAVE, rax

    ;;Save the current context

    ;;Save the SSE status and control flags
    stmxcsr MXCSR
	
    ;; Save registers:
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

execute_eenter:
	
    ;; Save the stack pointer so enclave can use the stack.
    mov STACKPTR, rsp

    ;; EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov rbx, TCS
    mov rcx, AEP
    mov rdi, ARG1
    mov rsi, ARG2
    mov rax, ENCLU_EENTER
    ENCLU

    mov ARG1OUT, rdi
    mov ARG2OUT, rsi
	
    ;; Restore the saved MXCSR
    ldmxcsr MXCSR
	
dispatch_ocall:

    ;; RAX = __oe_dispatch_ocall(
    ;;     RCX=arg1
    ;;     RDX=arg2
    ;;     R8=arg1_out
    ;;     R9=arg2_out
    ;;     [RSP+32]=TCS,
    ;;     [RSP+40]=ENCLAVE);
    sub rsp, 56
    mov rcx, ARG1OUT
    mov rdx, ARG2OUT
    lea r8, qword ptr ARG1OUT
    lea r9, qword ptr ARG2OUT
    mov rax, qword ptr TCS
    mov qword ptr [rsp+32], rax
    mov rax, qword ptr ENCLAVE
    mov qword ptr [rsp+40], rax
    call __oe_dispatch_ocall ;; RAX contains return value
    add rsp, 56

    ;; Restore the stack pointer:
    mov rsp, STACKPTR

    ;; If this was not an OCALL, then return from ECALL.
    cmp rax, 0
    jne return_from_ecall

    ;; Prepare to reenter the enclave, calling the entry point.
    mov rax, ARG1OUT
    mov ARG1, rax
    mov rax, ARG2OUT
    mov ARG2, rax
    jmp execute_eenter

return_from_ecall:

    ;; Set ARG3 (out)
    mov rbx, ARG1OUT
    mov rax, qword ptr [rbp+48]
    mov qword ptr [rax], rbx

    ;; Set ARG4 (out)
    mov rbx, ARG2OUT
    mov rax, qword ptr [rbp+56]
    mov qword ptr [rax], rbx

    ;; Restore registers:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx


    ;; Return parameters space:
    add rsp, PARAMS_SPACE

    ;; Restore stack frame:
    pop rbp

    BEGIN_EPILOGUE
    ret

NESTED_END oe_enter, _TEXT$00

END
