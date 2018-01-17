include ksamd64.inc

extern __OE_DispatchOCall:proc

;;==============================================================================
;;
;; void OE_Enter(
;;     [IN] void* tcs,
;;     [IN] void (*aep)(),
;;     [IN] uint64_t arg1,
;;     [IN] uint64_t arg2,
;;     [OUT] uint64_t* arg3,
;;     [OUT] uint64_t* arg4);
;;
;; Registers:
;;     RCX      - tcs: thread control structure (extended)
;;     RDX      - aep: asynchronous execution procedure
;;     R8       - arg1
;;     R9       - arg2
;;     [RBP+48] - arg3
;;     [RBP+56] - arg4
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
ARG1OUT         EQU [rbp-56]
ARG2OUT         EQU [rbp-64]
_RSP            EQU [rbp-72]

NESTED_ENTRY OE_Enter, _TEXT$00
    END_PROLOGUE

    ;; Setup stack frame:
    push rbp
    mov rbp, rsp

    ;; Save parameters on stack for later reference:
    sub rsp, PARAMS_SPACE
    mov TCS, rdi
    mov AEP, rsi
    mov ARG1, rdx
    mov ARG2, rcx
    mov ARG3, r8
    mov ARG4, r9

    ;; Save registers:
    push rbx

execute_eenter:

    ;; Save the stack pointer so enclave can use the stack.
    mov _RSP, rsp

    ;; EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov rbx, TCS
    mov rcx, AEP
    mov rdi, ARG1
    mov rsi, ARG2
    mov rax, ENCLU_EENTER
    ENCLU

    mov ARG1OUT, rdi
    mov ARG2OUT, rsi

dispatch_ocall:

    ;; Save registers that could get clobbered below or by function call.
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push r8
    push r9
    push r12
    push r13

    ;; Call __OE_DispatchOCall():
    ;;     RDI=arg1
    ;;     RSI=arg2
    ;;     RDX=arg1Out
    ;;     RCX=arg2Out
    ;;     R8=TCS
    ;;     R9=RSP
    mov rdi, ARG1OUT
    mov rsi, ARG2OUT
    lea rdx, ARG1OUT      ;; ATTN: ported 'leaq' to 'lea'!
    lea rcx, ARG2OUT      ;; ATTN: ported 'leaq' to 'lea'!
    mov r8, TCS
    mov r9, _RSP
    call __OE_DispatchOCall

    ;; Restore registers (except RDI and RSI)
    pop r13
    pop r12
    pop r9
    pop r8
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi

    ;; Restore the stack pointer:
    mov rsp, _RSP

    ;; If this was not an OCALL, then return from ECALL.
    cmp rax, 0
    jne return_from_ecall

    ;; Execute EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    mov rax, ARG1OUT
    mov ARG1, rax
    mov rax, ARG2OUT
    mov ARG2, rax
    jmp execute_eenter

return_from_ecall:

    ;; Set output parameters:
    mov rax, ARG1OUT
    mov [r8], rax
    mov rax, ARG2OUT
    mov [r9], rax

    ;; Restore registers:
    pop rbx

    ;; Return parameters space:
    add rsp, PARAMS_SPACE

    ;; Restore stack frame:
    pop rbp

    BEGIN_EPILOGUE
    ret

NESTED_END OE_Enter, _TEXT$00

END
