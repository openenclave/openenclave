;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

ENCLU_EREPORT                   EQU 0

;;=============================================================================
;;
;; jump buffer fields - must match exactly the lay of oe_jumpbuf_t
;;
;;=============================================================================
jb_t struct
    _rsp        dq ?
    _rbp        dq ?
    _rip        dq ?
    _rbx        dq ?
    _r12        dq ?
    _r13        dq ?
    _r14        dq ?
    _r15        dq ?
    _rdi        dq ?
    _rsi        dq ?
    _frmptr     dq ?
    _mxcsr      dd ?
    sparc       dd ?
    _xmm6       oword ?
    _xmm7       oword ?
    _xmm8       oword ?
    _xmm9       oword ?
    _xmm10      oword ?
    _xmm11      oword ?
    _xmm12      oword ?
    _xmm13      oword ?
    _xmm14      oword ?
    _xmm15      oword ?
jb_t ends

;;=============================================================================
;;
;; oe_setjmp()
;;
;;=============================================================================
LEAF_ENTRY oe_setjmp, _TEXT$00
    lea     r8, [rsp+8]             ;; rsp *before* making the call
    mov     r9, [rsp]               ;; rip == return address.
    mov     [rcx].jb_t._rsp, r8
    mov     [rcx].jb_t._rbp, rbp
    mov     [rcx].jb_t._rip, r9
    mov     [rcx].jb_t._rbx, rbx
    mov     [rcx].jb_t._r12, r12
    mov     [rcx].jb_t._r13, r13
    mov     [rcx].jb_t._r14, r14
    mov     [rcx].jb_t._r15, r15
    mov     [rcx].jb_t._rdi, rdi
    mov     [rcx].jb_t._rsi, rsi
    mov     [rcx].jb_t._frmptr, rbp     ;; frame pointer before making the call
    stmxcsr [rcx].jb_t._mxcsr           ;; save MXCSR
    movdqu  [rcx].jb_t._xmm6, xmm6
    movdqu  [rcx].jb_t._xmm7, xmm7
    movdqu  [rcx].jb_t._xmm8, xmm8
    movdqu  [rcx].jb_t._xmm9, xmm9
    movdqu  [rcx].jb_t._xmm10, xmm10
    movdqu  [rcx].jb_t._xmm11, xmm11
    movdqu  [rcx].jb_t._xmm12, xmm12
    movdqu  [rcx].jb_t._xmm13, xmm13
    movdqu  [rcx].jb_t._xmm14, xmm14
    movdqu  [rcx].jb_t._xmm15, xmm15
    xor     eax, eax                    ;; set return value
    ret
LEAF_END oe_setjmp, _TEXT$00

;;=============================================================================
;;
;; oe_longjmp()
;;
;;=============================================================================
LEAF_ENTRY oe_longjmp, _TEXT$00
    mov     rbx, [rcx].jb_t._rbx
    mov     r12, [rcx].jb_t._r12
    mov     r13, [rcx].jb_t._r13
    mov     r14, [rcx].jb_t._r14
    mov     r15, [rcx].jb_t._r15
    mov     rdi, [rcx].jb_t._rdi
    mov     rsi, [rcx].jb_t._rsi
    ldmxcsr [rcx].jb_t._mxcsr           ;; restore MXCSR
    movdqu  xmm6, [rcx].jb_t._xmm6
    movdqu  xmm7, [rcx].jb_t._xmm7
    movdqu  xmm8, [rcx].jb_t._xmm8
    movdqu  xmm9, [rcx].jb_t._xmm9
    movdqu  xmm10, [rcx].jb_t._xmm10
    movdqu  xmm11, [rcx].jb_t._xmm11
    movdqu  xmm12, [rcx].jb_t._xmm12
    movdqu  xmm13, [rcx].jb_t._xmm13
    movdqu  xmm14, [rcx].jb_t._xmm14
    movdqu  xmm15, [rcx].jb_t._xmm15
    test    edx, edx
    jnz     short @f
    inc     edx                     ;; return value cannot be 0
@@:
    mov     eax, edx                ;; set return value
    mov     rbp, [rcx].jb_t._rbp
    mov     rsp, [rcx].jb_t._rsp
    mov     r8,  [rcx].jb_t._rip
    jmp     r8
LEAF_END oe_longjmp, _TEXT$00

;;==============================================================================
;;
;; void oe_issue_sgx_ereport(
;;    sgx_target_info_t* ti,
;;    sgx_report_data_t* rd,
;;    sgx_report_t* r);
;;
;; Registers:
;;     RCX - ti
;;     RDX - ri
;;     R8 - r
;;
;; Purpose:
;;     Issue EREPROT instruction.
;;
;;==============================================================================

NESTED_ENTRY oe_issue_sgx_ereport, _TEXT$00
    ;; Setup stack frame:
    rex_push_reg rbx
    END_PROLOGUE

    ;; EREPROT(RAX=EREPROT, RBX=ti, RCX=rd, RDX=r)
    mov     eax, ENCLU_EREPORT
    mov     rbx, rcx
    mov     rcx, rdx
    mov     rdx, r8
    ENCLU

    BEGIN_EPILOGUE
    pop     rbx
    ret

NESTED_END oe_issue_sgx_ereport, _TEXT$00

;;=============================================================================
;;
;; oe_exception_dispatcher()
;;
;; TODO: implement.
;;
;;=============================================================================
LEAF_ENTRY oe_exception_dispatcher, _TEXT$00
    ret
LEAF_END oe_exception_dispatcher, _TEXT$00

END
