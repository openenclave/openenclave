;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

extern __oe_handle_main_wrap:proc

OE_WORD_SIZE                    EQU 8
OE_PAGE_SIZE                    EQU 01000h
OE_SSA_FROM_TCS_BYTE_OFFSET     EQU OE_PAGE_SIZE
OE_TD_FROM_TCS_BYTE_OFFSET      EQU 4*OE_PAGE_SIZE
OE_DEFAULT_SSA_FRAME_SIZE       EQU 1
OE_SGX_GPR_BYTE_SIZE            EQU 0b8h
OE_SGX_TCS_HEADER_BYTE_SIZE     EQU 048h
SGX_SSA_RSP_OFFSET              EQU 0F68h

ENCLU_EEXIT                     EQU 4

;;
;; td_t MUST MATCH the td_t definition in sgxtypes.h
;;
td_t struct
    self_addr           dq ?
    last_sp             dq ?
    internal            db 152 dup (?) ;; unused oe_thread_data_t fields
    magic               dq ?
    depth               dq ?
    host_rcx            dq ?    ;; EENTER return address
    host_rsp            dq ?
    host_rbp            dq ?
    host_prev_rsp       dq ?
    host_prev_rbp       dq ?
    oret_func           dq ?    ;; oret_func,oret_result, and paddig
    oret_arg            dq ?
    callsites           dq ?
    simulate            dq ?
    ;; subsequent field unused.
td_t ends

;;
;; enc_args_t MUST MATCH the oe_ecall_enc_args_t definition in asmdefs.h
;;
enc_args_t struct
    cssa                dq ?
    tcs                 dq ?
    arg1                dq ?
    arg2                dq ?
    arg1_out            dq ?
    arg2_out            dq ?
enc_args_t ends

;;==============================================================================
;;
;; oe_entry(RAX=CSSA, R10=TCS, RCX=RETADDR, RDI=ARG1, RSI=ARG2)
;;
;;     The EENTER instruction (executed by the host) calls this function to
;;     enter the enclave.
;;
;;     Registers from EENTER:
;;         RAX - index of current SSA (CSSA)
;;         RBX - address of TCS (TCS)
;;         RCX - address of instruction following EENTER (RETADDR)
;;
;;     Registers from host caller of EENTER:
;;         RDI - ARG1
;;         RSI - ARG2
;;
;;     Free to use any register, except rbp and rsp, without save/restore, as
;;     Enclave ABI requires host to save/restore all non-volatiles.
;;==============================================================================

LEAF_ENTRY oe_entry, _TEXT$00

    ;; Do a one-time update to last_sp such that we can always use last_sp
    ;; upon regular entrance.
    ;; TODO: Update td_init and td_clear to not change last_sp.
    cmp     qword ptr gs:[td_t.last_sp], 0
    jnz     short save_host_registers

    ;; First entrance from this TCS. initialize last_sp
    lea     r14, [rbx-OE_PAGE_SIZE]

    mov     gs:[td_t.last_sp], r14

save_host_registers:
    ;; Save host registers (restored on EEXIT)
    mov     gs:[td_t.host_rcx], rcx
    mov     r8, gs:[td_t.host_rbp]
    mov     r9, gs:[td_t.host_rsp]
    mov     gs:[td_t.host_rbp], rbp
    mov     gs:[td_t.host_rsp], rsp
    mov     gs:[td_t.host_prev_rbp], r8
    mov     gs:[td_t.host_prev_rsp], r9

    test    rax, rax
    jne     exception_entry

    ;; Not exception entry, use last_sp.
    mov     r14, gs:[td_t.last_sp]

align_stack:
    ;; Stop speculative execution.
    lfence

    ;; align stack, original rsp saved in r14
    mov     rsp, r14
    and     rsp, -16

setup_arguments:
    .errnz (size enc_args_t AND 0fh)

    ;; Allocate space for oe_ecall_enc_args_t
    sub     rsp, size enc_args_t

    mov     r12, rsp    ;; r12 = ptr to oe_ecall_enc_args_t
    mov     [r12].enc_args_t.cssa, rax
    mov     [r12].enc_args_t.tcs,  rbx
    mov     [r12].enc_args_t.arg1, rdi
    mov     [r12].enc_args_t.arg2, rsi

call_handler_main:

    ;; VC calling convention, room for args
    sub     rsp, 4*8

    ;; Call __oe_handle_main
    mov     rcx, r12
    call    __oe_handle_main_wrap

    ;; setup return argument and reclaim stack
    mov     rdi, [r12].enc_args_t.arg1_out
    mov     rsi, [r12].enc_args_t.arg2_out

    ;; Restore rsp
    mov     rsp, r14

    ;; Exit Enclave
    jmp     __oe_exit

exception_entry:
    ;; Stop speculative execution.
    lfence

    ;; Get the first ssa address from tcs.
    lea     r8, OE_SSA_FROM_TCS_BYTE_OFFSET[rbx]

    ;; Get the offset of current SSA from the begining of the SSA.
    dec     rax
    shl     rax, 12

    ;; Get the address of current SSA.
    add     rax, r8

    ;; Get the saved rsp. We can't depend on the TLS value to get the enclave
    ;; rsp in exception entry since the value may not be set correctly.
    mov     r14, SGX_SSA_RSP_OFFSET[rax]
    jmp     align_stack

LEAF_END oe_entry, _TEXT$00

;;==============================================================================
;; __oe_exit - final step of leaving Enclave
;; Non-standard arguments (Enclave ABI):
;;      - RDI: return argument 1
;;        RSI: return argument 2
;;
;;==============================================================================
LEAF_ENTRY __oe_exit, _TEXT$00

    ;; Update last_sp
    mov     gs:[td_t.last_sp], rsp

    ;; Clear general purpose registers, except
    ;; - rax, rbx: EEXIT argument register (SGX ABI)
    ;; - rsi, rdi: OE argument registers (OE ABI)
    ;; - rsp, rbp: Reload with preserved host registers values.
    xor     rcx, rcx
    xor     rdx, rdx
    xor     r8 , r8
    xor     r9 , r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15

    ;; Clear xmm registers
    xorps   xmm0,  xmm0
    xorps   xmm1,  xmm1
    xorps   xmm2,  xmm2
    xorps   xmm3,  xmm3
    xorps   xmm4,  xmm4
    xorps   xmm5,  xmm5
    xorps   xmm6,  xmm6
    xorps   xmm7,  xmm7
    xorps   xmm8,  xmm8
    xorps   xmm9,  xmm9
    xorps   xmm10, xmm10
    xorps   xmm11, xmm11
    xorps   xmm12, xmm12
    xorps   xmm13, xmm13
    xorps   xmm14, xmm14
    xorps   xmm15, xmm15

    ;; Restore host registers
    mov     rbp, gs:[td_t.host_rbp]
    mov     rsp, gs:[td_t.host_rsp]

    ;; EEXIT(RAX=EEXIT, RBX=RETADDR, RDI=ARG1, RSI=ARG2)
    mov     rax, ENCLU_EEXIT
    mov     rbx, gs:[td_t.host_rcx]
    ENCLU

    ;; Never return
    int     3

loopforever:
    jmp     short loopforever

LEAF_END __oe_exit, _TEXT$00

;;==============================================================================
;;
;; void oe_exit(uint64_t arg1, uint64_t arg2)
;;
;; Registers:
;;     RCX - arg1
;;     RDX - arg2
;;
;; Purpose:
;;     Restores user registers and executes the EEXIT instruction to leave the
;;     enclave and return control to the host. This function is called for two
;;     reasons:
;;
;;         (1) To perform an OCALL.
;;         (2) To perform an ABORT (oe_abort).
;; 
;;     Regular ERET will return from __oe_handle_main and exit from oe_entry.
;;
;; Tasks:
;;         (1) Push rbp to provide a linkage to previous funciton.
;;      Convert VC arguments (rcx, rdx) to Enclave ABI arguments (rdi, rsi)
;;      and jump to the common exit path.
;;
;;      N.B. (1) OCALL is done via oe_setjump/oe_longjmp and registers will be
;;               restored when oe_longjmp is executed.
;;           (2) Upon abort, Enclave registers doesn't matter anymore as we will
;;               not resume from the aborting point.
;;
;;           i.e. no register needs to be preserved, except rsp, when oe_exit is
;;                called.
;;
;;==============================================================================

NESTED_ENTRY oe_exit, _TEXT$00
    ;; Setup stack frame:
    rex_push_reg rbp
    set_frame    rbp, 0
    END_PROLOGUE

    ;; Setup rdi/rsi as return value per Enclave ABI
    mov     rdi, rcx
    mov     rsi, rdx

    BEGIN_EPILOGUE

    ;; return to host
    jmp     __oe_exit

NESTED_END oe_exit, _TEXT$00

END
