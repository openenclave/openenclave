;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

extern __oe_dispatch_ocall:proc

;;==============================================================================
;;
;; void oe_enter(
;;     [INOUT] oe_ecall_args_t* ecall_args);
;;
;; Registers:
;;     RCX      - ecall_args: poiter to ecall_args_t structure
;;
;; Standard Virtual C calling convention for general purpose registers
;;          (non-volatiles: rbx, rdi, rsi, r12-r15).
;;
;;==============================================================================

;;
;; earg_t MUST MATCH the ecall_args_t definition in asmdefs.h
;;
earg_t struct
    tcs                 dq ?
    enclave             dq ?
    aep                 dq ?
    arg1                dq ?
    arg2                dq ?
    arg1_out            dq ?
    arg2_out            dq ?
earg_t ends

efrm_t struct
    cparams             dq 4 dup(?)     ;; 4 parameter save area for C calling convention.
    ecall_args          dq ?            ;; to save ecall_args on stack.

    ;; Non-volatile general purpose registers
    _rbx                dq ?
    _rdi                dq ?
    _rsi                dq ?
    _r12                dq ?
    _r13                dq ?
    _r14                dq ?
    _r15                dq ?

    ;; Non-volatile XMM registers
    _xmm6               oword ?
    _xmm7               oword ?
    _xmm8               oword ?
    _xmm9               oword ?
    _xmm10              oword ?
    _xmm11              oword ?
    _xmm12              oword ?
    _xmm13              oword ?
    _xmm14              oword ?
    _xmm15              oword ?
efrm_t ends

ENCLU_EENTER    EQU     2

;;
;; oe_enter function
;;
NESTED_ENTRY oe_enter, _TEXT$00

    ;; Setup stack frame:
    rex_push_reg rbp
    set_frame    rbp, 0

    ;; allocate stack
    alloc_stack size efrm_t

    ;; Save all volatile registers
    save_reg    rbx, efrm_t._rbx
    save_reg    rdi, efrm_t._rdi
    save_reg    rsi, efrm_t._rsi
    save_reg    r12, efrm_t._r12
    save_reg    r13, efrm_t._r13
    save_reg    r14, efrm_t._r14
    save_reg    r15, efrm_t._r15
    save_xmm128 xmm6, efrm_t._xmm6
    save_xmm128 xmm7, efrm_t._xmm7
    save_xmm128 xmm8, efrm_t._xmm8
    save_xmm128 xmm9, efrm_t._xmm9
    save_xmm128 xmm10, efrm_t._xmm10
    save_xmm128 xmm11, efrm_t._xmm11
    save_xmm128 xmm12, efrm_t._xmm12
    save_xmm128 xmm13, efrm_t._xmm13
    save_xmm128 xmm14, efrm_t._xmm14
    save_xmm128 xmm15, efrm_t._xmm15

    END_PROLOGUE

    ;; Stack must be 16-bytes aligned.
    .errnz  (size efrm_t AND 0Fh)

    ;; save ecall_args
    mov     [rsp].efrm_t.ecall_args, rcx

    ;; N.B. stack must be 16-byte aligned. Make sure the prolog
    ;;      do it correctly.

    ;; Use non-volatile register for ecall args.
    mov     r12, rcx

execute_eenter:

    ;; EENTER(RAX=EENTER, RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2)
    ;; (r12) = ecall_args
    mov     rax, ENCLU_EENTER
    mov     rbx, [r12].earg_t.tcs
    mov     rcx, [r12].earg_t.aep
    mov     rdi, [r12].earg_t.arg1
    mov     rsi, [r12].earg_t.arg2
    ENCLU

    ;; Reload ecall_args.
    ;; N.B. Enclave ABI only guarantee to preserve RSP and RBP.
    mov     r12, [rsp].efrm_t.ecall_args

    ;; save return arguments (rdi, rsi)
    mov     [r12].earg_t.arg1_out, rdi
    mov     [r12].earg_t.arg2_out, rsi

    ;; eax = __oe_dispatch_ocall(
    ;;              rcx = ecall_args);
    ;; N.B. __oe_dispatch_ocall returns "int"

    mov     rcx, r12
    call    __oe_dispatch_ocall

    ;; Return to Enclave if this is an OCALL.
    test    eax, eax
    jz      short execute_eenter

    ;; Restore all non-volatile registers
    mov     rbx, [rsp]. efrm_t._rbx
    mov     rdi, [rsp]. efrm_t._rdi
    mov     rsi, [rsp]. efrm_t._rsi
    mov     r12, [rsp]. efrm_t._r12
    mov     r13, [rsp]. efrm_t._r13
    mov     r14, [rsp]. efrm_t._r14
    mov     r15, [rsp]. efrm_t._r15
    movdqu  xmm6, [rsp].efrm_t._xmm6
    movdqu  xmm7, [rsp].efrm_t._xmm7
    movdqu  xmm8, [rsp].efrm_t._xmm8
    movdqu  xmm9, [rsp].efrm_t._xmm9
    movdqu  xmm10, [rsp].efrm_t._xmm10
    movdqu  xmm11, [rsp].efrm_t._xmm11
    movdqu  xmm12, [rsp].efrm_t._xmm12
    movdqu  xmm13, [rsp].efrm_t._xmm13
    movdqu  xmm14, [rsp].efrm_t._xmm14
    movdqu  xmm15, [rsp].efrm_t._xmm15

    ;; Reclaim VC argument area 
    add     rsp,  size efrm_t

    BEGIN_EPILOGUE

    pop     rbp
    ret

NESTED_END oe_enter, _TEXT$00

END
