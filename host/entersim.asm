include ksamd64.inc

extern __OE_DispatchOCall:proc

;;==============================================================================
;;
;; void OE_EnterSim(
;;     [IN] void* tcs,
;;     [IN] void (*aep)(),
;;     [IN] uint64_t arg1,
;;     [IN] uint64_t arg2,
;;     [OUT] uint64_t* arg3,
;;     [OUT] uint64_t* arg4);
;;
;; Registers:
;;     RDI   - tcs: thread control structure (extended)
;;     RSI   - aep: asynchronous execution procedure
;;     RDX   - arg1
;;     RCX   - arg2
;;     R8    - arg3
;;     R9    - arg4
;;
;;==============================================================================

PARAMS_SPACE    EQU 128
TCS             EQU [rbp-8]
AEP             EQU [rbp-16]
ARG1            EQU [rbp-24]
ARG2            EQU [rbp-32]
ARG3            EQU [rbp-40]
ARG4            EQU [rbp-48]
ARG1OUT         EQU [rbp-56]
ARG2OUT         EQU [rbp-64]
CSSA            EQU [rbp-72]
_RSP            EQU [rbp-84]

NESTED_ENTRY OE_EnterSim, _TEXT$00
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
    mov rax, 0
    mov CSSA, rax

    ;; Save registers:
    push rbx

call_oe_main:

    ;; Save the stack pointer so enclave can use the stack.
    mov _RSP, rsp

    ;; Call OE_Main(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
    mov rax, CSSA
    mov rbx, TCS
    mov rdx, [rbx+72] ;; RDX=TCS.u.main (72)
    mov rdi, ARG1
    mov rsi, ARG2
    lea rcx, retaddr
    jmp rdx ;; ATTN: review for correctness!
retaddr:
    mov ARG1OUT, rdi
    mov ARG2OUT, rsi

dispatch_ocall_sim:

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
    mov rdi, ARG1OUT
    mov rsi, ARG2OUT
    lea rdx, ARG1OUT ;; ATTN: review for correctness! Had to remove 'q' suffix
    lea rcx, ARG2OUT ;; ATTN: review for correctness! Had to remove 'q' suffix
    mov r8, TCS
    call __OE_DispatchOCall

    ;; Restore registers saved above:
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
    jne return_from_ecall_sim

    ;; (RDI=TCS, RDX=ARG1, RCX=ARG2)
    mov rax, ARG1OUT
    mov ARG1, rax
    mov rax, ARG2OUT
    mov ARG2, rax
    jmp call_oe_main

return_from_ecall_sim:

    ;; Set output parameters:
    mov rax, ARG1OUT
    mov [r8], rax ;; arg3
    mov rax, ARG2OUT
    mov [r9], rax ;; arg4

    ;; Restore registers:
    pop rbx

    ;; Return parameters space:
    add rsp, PARAMS_SPACE

    ;; Restore stack frame:
    pop rbp

    BEGIN_EPILOGUE
    ret

NESTED_END OE_EnterSim, _TEXT$00

END
