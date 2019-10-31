;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

extern __oe_dispatch_ocall:proc

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
;;     RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15 and XMM6-15
;; See https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
;;==============================================================================

ENCLU_EENTER    EQU 2
OE_OCALL_CODE   EQU 3

ARG3      EQU [rbp+6*8]
ARG4      EQU [rbp+7*8]
ENCLAVE   EQU [rbp+8*8]

TCS             EQU [rbp-1*8]
AEP             EQU [rbp-2*8]
ARG1            EQU [rbp-3*8]
ARG2            EQU [rbp-4*8]
FX_SPACE        EQU [rbp-68*8] ;; 512 bytes needed for fx
PARAMS_SPACE    EQU (68*8)

NESTED_ENTRY oe_enter, _TEXT$00
    END_PROLOGUE

    ;; Setup stack frame:
    push rbp ;; Stack is 16-byte aligned at this point
    mov rbp, rsp

    ;; Save parameters on stack for later reference:
    sub rsp, PARAMS_SPACE
    mov TCS, rcx
    mov AEP, rdx
    mov ARG1, r8
    mov ARG2, r9

    ;; Save x64 Windows ABI callee saved registers
    push r15
    push r14
    push r13
    push r12
    push rsi
    push rdi
    push rbx
    push rbx ;; Align stack to 16-byte boundary

execute_eenter:
    ;; Save flags. Floating point state has already been saved.
    fxsave FX_SPACE
    pushfq

    ;; EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov rbx, TCS
    mov rcx, AEP
    mov rdi, ARG1
    mov rsi, ARG2
    mov rax, ENCLU_EENTER
    ENCLU

    ;; Save return values
    mov ARG1, rdi
    mov ARG2, rsi

    ;; Restore flags and floating point state.
    popfq
    fxrstor FX_SPACE

    ;; Check if an OCALL needs to be dispatched.
    mov r10, rdi
    shr r10, 48
    cmp r10, OE_OCALL_CODE
    jne return_from_ecall

dispatch_ocall:
    ;; RAX = __oe_dispatch_ocall(
    ;;     RCX=arg1
    ;;     RDX=arg2
    ;;     R8=&arg1
    ;;     R9=&arg2
    ;;     [RSP+32]=TCS,
    ;;     [RSP+40]=ENCLAVE);
    ;;
    ;; Stack should already be 16-byte aligned, so only need
    ;; shadow space (32 bytes) plus stack params size (16 bytes)
    sub rsp, 48
    mov rcx, rdi
    mov rdx, rsi
    lea r8, ARG1
    lea r9, ARG2
    mov rax, qword ptr TCS
    mov qword ptr [rsp+32], rax
    mov rax, ENCLAVE
    mov [rsp+40], rax
    call __oe_dispatch_ocall ;; RAX contains return value
    add rsp, 48

    jmp execute_eenter

return_from_ecall:
    ;; Write results
    ;; RSI contains arg1, RDI contains arg2
    mov rbx, ARG3
    mov [rbx], rdi
    mov rcx, ARG4
    mov [rcx], rsi

    ;; Restore callee saved registers
    fxrstor FX_SPACE
    pop rbx
    pop rbx
    pop rdi
    pop rsi
    pop r12
    pop r13
    pop r14
    pop r15

    ;; Restore stack frame
    mov rsp, rbp
    pop rbp

    BEGIN_EPILOGUE
    ret

NESTED_END oe_enter, _TEXT$00

END
