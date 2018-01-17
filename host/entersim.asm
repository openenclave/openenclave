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
;;     RCX      - tcs: thread control structure (extended)
;;     RDX      - aep: asynchronous execution procedure
;;     R8       - arg1
;;     R9       - arg2
;;     [RBP+48] - arg3
;;     [RBP+56] - arg4
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
TCS_u_main      EQU 72

NESTED_ENTRY OE_EnterSim, _TEXT$00
    END_PROLOGUE

    ;; Setup stack frame:
    push rbp
    mov rbp, rsp

    ;; Layout of stack at this point (per Microsoft x64 calling convention)
    ;;     [ RBP          ] [RBP+0]
    ;;     [ RETURN-VALUE ] [RBP+8]
    ;;     [ SHADOW-SPACE ] [RBP+16]
    ;;     [ SHADOW-SPACE ] [RBP+24]
    ;;     [ SHADOW-SPACE ] [RBP+32]
    ;;     [ SHADOW-SPACE ] [RBP+40]
    ;;     [ ARG3         ] [RBP+48]
    ;;     [ ARG4         ] [RBP+56]

    ;; Save parameters on stack for later reference:
    ;;     TCS  := [RBP-8]  <- RCX
    ;;     AEP  := [RBP-16] <- RDX
    ;;     ARG1 := [RBP-24] <- R8
    ;;     ARG2 := [RBP-32] <- R9
    ;;     ARG3 := [RBP-40] <- [RBP+48]
    ;;     ARG4 := [RBP-48] <- [RBP+56]
    ;;
    sub rsp, PARAMS_SPACE
    mov TCS, rcx
    mov AEP, rdx
    mov ARG1, r8
    mov ARG2, r9
    mov rax, [rbp+48]
    mov ARG3, rax
    mov rax, [rbp+56]
    mov ARG4, rax

    ;; Load CSSA with zero initially:
    mov rax, 0
    mov CSSA, rax

    ;; Save registers:
    push rbx

call_oe_main:

    ;; Save the stack pointer so enclave can use the stack.
    mov _RSP, rsp

    ;; Call OE_Main(RAX=CSSA, RBX=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2) in enclave
    mov rax, CSSA
    mov rbx, TCS
    lea rcx, retaddr
    mov rdi, ARG1
    mov rsi, ARG2
    jmp qword ptr [rbx+TCS_u_main]
retaddr:
    mov CSSA, rax ;; ATTN: new
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

    ;; Call __OE_DispatchOCall() using Microsoft X64 calling convention:
    ;;     RCX=arg1
    ;;     RDX=arg2
    ;;     R8=arg1Out
    ;;     R9=arg2Out
    ;;     [RSP+32]=TCS
    sub rsp, 56
    mov rcx, ARG1OUT
    mov rdx, ARG2OUT
    lea r8, qword ptr ARG1OUT
    lea r9, qword ptr ARG2OUT
    mov rax, qword ptr TCS
    mov qword ptr [rsp+32], rax
    call __OE_DispatchOCall
    add rsp, 56

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
    mov rax, CSSA ;; ATTN: new
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
    mov rbx, ARG1OUT
    mov rax, qword ptr [rbp+48]
    mov qword ptr [rax], rbx
    mov rbx, ARG2OUT
    mov rax, qword ptr [rbp+56]
    mov qword ptr [rax], rbx

    ;; Restore registers:
    pop rbx

    ;; Return parameters space:
    add rsp, PARAMS_SPACE

    ;; Restore stack frame:
    pop rbp

    BEGIN_EPILOGUE
    ret

forever:
    jmp forever

NESTED_END OE_EnterSim, _TEXT$00

END
