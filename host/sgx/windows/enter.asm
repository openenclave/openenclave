;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

extern __oe_dispatch_ocall:proc
extern oe_save_host_context:proc
extern oe_restore_host_context:proc

;;==============================================================================
;;
;; void oe_enter(
;;     [IN] void* tcs,
;;     [IN] uint64_t aep,
;;     [IN] uint64_t arg1,
;;     [IN] uint64_t arg2,
;;     [OUT] uint64_t* arg3,
;;     [OUT] uint64_t* arg4,
;;     [OUT] oe_enclave_t* enclave);
;;
;; Parameters passed on register and stack:
;;     RCX      - tcs: thread control structure (extended)
;;     RDX      - aep: asynchronous execution procedure
;;     R8       - arg1
;;     R9       - arg2
;;     [RBP+48] - arg3
;;     [RBP+56] - arg4
;;     [RBP+64] - enclave
;;
;; These registers may be destroyed across function calls:
;;     RAX, RCX, RDX, R8, R9, R10, R11
;;
;; These registers must be preserved across function calls:
;;     RBX, RBP, RDI, RSI, RSP, R12, R13, R14, and R15
;;
;;==============================================================================

ENCLU_EENTER    EQU 2

ARG3_PARAM      EQU [rbp+48]
ARG4_PARAM      EQU [rbp+56]
ENCLAVE_PARAM   EQU [rbp+64]

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
HOST_CONTEXT    EQU [rbp-88]

;; Reserve parameter space based on:
;; + 88 bytes for 11*8-byte parameters TCS to HOST_CONTEXT
;; HOST_CONTEXT points to the start of the context data consisting of:
;; + 64 bytes for 8*8-byte callee-preserved registers
;; + 512-byte OE_CONTEXT_FLOAT memory image used in fxsave/fxrstor
;; + 8 bytes so that the stack remains 16-byte aligned.
PARAMS_SPACE    EQU 672

NESTED_ENTRY oe_enter, _TEXT$00
    END_PROLOGUE

    ;; Setup stack frame:
    push rbp ;; Stack is 16-byte aligned at this point
    mov rbp, rsp

    ;; Save parameters on stack for later reference:
    ;;     TCS  := [RBP-8]  <- RCX
    ;;     AEP  := [RBP-16] <- RDX
    ;;     ARG1 := [RBP-24] <- R8
    ;;     ARG2 := [RBP-32] <- R9
    ;;     ARG3 := [RBP-40] <- ARG3_PARAM := [RBP+48]
    ;;     ARG4 := [RBP-48] <- ARG4_PARAM := [RBP+56]
    ;;     ENCLAVE := [RBP-56] <- ENCLAVE_PARAM := [RBP+64]
    ;;     HOST_CONTEXT := [RBP-88]
    sub rsp, PARAMS_SPACE
    mov TCS, rcx
    mov AEP, rdx
    mov ARG1, r8
    mov ARG2, r9
    mov rax, ARG3_PARAM
    mov ARG3, rax
    mov rax, ARG4_PARAM
    mov ARG4, rax
    mov rax, ENCLAVE_PARAM
    mov ENCLAVE, rax

    ;; Set the save location for the host context on the host stack
    mov HOST_CONTEXT, rsp

execute_eenter:

    ;; Save the current host context
    mov rcx, HOST_CONTEXT
    call oe_save_host_context

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

    ;; Restore the saved host context
    mov rcx, HOST_CONTEXT
    call oe_restore_host_context

dispatch_ocall:
    ;; RAX = __oe_dispatch_ocall(
    ;;     RCX=arg1
    ;;     RDX=arg2
    ;;     R8=arg1_out
    ;;     R9=arg2_out
    ;;     [RSP+32]=TCS,
    ;;     [RSP+40]=ENCLAVE);
    ;;
    ;; Stack should already be 16-byte aligned, so only need
    ;; shadow space (32 bytes) plus stack params size (16 bytes)
    sub rsp, 48
    mov rcx, ARG1OUT
    mov rdx, ARG2OUT
    lea r8, qword ptr ARG1OUT
    lea r9, qword ptr ARG2OUT
    mov rax, qword ptr TCS
    mov qword ptr [rsp+32], rax
    mov rax, qword ptr ENCLAVE
    mov qword ptr [rsp+40], rax
    call __oe_dispatch_ocall ;; RAX contains return value
    add rsp, 48

    ;; Restore the stack pointer
    mov rsp, STACKPTR

    ;; If this was not an OCALL, then return from ECALL.
    cmp rax, 0
    jne return_from_ecall

    ;; Stop speculative execution at fallthrough of conditional check
    lfence

    ;; Prepare to reenter the enclave, calling the entry point.
    mov rax, ARG1OUT
    mov ARG1, rax
    mov rax, ARG2OUT
    mov ARG2, rax
    jmp execute_eenter

return_from_ecall:
    ;; Stop speculative execution at target of conditional jump
    lfence

    ;; Set ARG3 (out)
    mov r10, ARG1OUT
    mov rax, qword ptr ARG3_PARAM
    mov qword ptr [rax], r10

    ;; Set ARG4 (out)
    mov r10, ARG2OUT
    mov rax, qword ptr ARG4_PARAM
    mov qword ptr [rax], r10

    ;; Return parameters space and restore the stack pointer
    mov rsp, rbp

    ;; Restore stack frame
    pop rbp

    BEGIN_EPILOGUE
    ret

NESTED_END oe_enter, _TEXT$00

END
