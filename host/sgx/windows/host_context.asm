;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

OE_CONTEXT_FLAGS    EQU 00
OE_CONTEXT_RBX      EQU 08
OE_CONTEXT_RDI      EQU 16
OE_CONTEXT_RSI      EQU 24
OE_CONTEXT_R12      EQU 32
OE_CONTEXT_R13      EQU 40
OE_CONTEXT_R14      EQU 48
OE_CONTEXT_R15      EQU 56
OE_CONTEXT_FLOAT    EQU 64

.CODE

PUBLIC oe_save_host_context
oe_save_host_context PROC
    ;; Subroutine prologue
    push rbp
    mov rbp, rsp

    ;; Save the flags to stack.
    pushf
    mov rax, [rsp]
    mov [rcx+OE_CONTEXT_FLAGS], rax
    popf

    ;; Save general registers.
    mov [rcx+OE_CONTEXT_RBX], rbx
    mov [rcx+OE_CONTEXT_RDI], rdi
    mov [rcx+OE_CONTEXT_RSI], rsi
    mov [rcx+OE_CONTEXT_R12], r12
    mov [rcx+OE_CONTEXT_R13], r13
    mov [rcx+OE_CONTEXT_R14], r14
    mov [rcx+OE_CONTEXT_R15], r15

    ;; Save x87 FPU, MMX and SSE state (includes MXCSR and XMM registers).
    fxsave [rcx+OE_CONTEXT_FLOAT]

    ;; Subroutine epilogue
    mov rsp, rbp
    pop rbp
    ret

oe_save_host_context ENDP

PUBLIC oe_restore_host_context
oe_restore_host_context PROC

    ;; Subroutine prologue
    push rbp
    mov rbp, rsp

    ;; Restore the flags to stack.
    push [rcx+OE_CONTEXT_FLAGS]
    popfq

    ;; Restore general registers.
    mov rbx, [rcx+OE_CONTEXT_RBX]
    mov rdi, [rcx+OE_CONTEXT_RDI]
    mov rsi, [rcx+OE_CONTEXT_RSI]
    mov r12, [rcx+OE_CONTEXT_R12]
    mov r13, [rcx+OE_CONTEXT_R13]
    mov r14, [rcx+OE_CONTEXT_R14]
    mov r15, [rcx+OE_CONTEXT_R15]

    ;; Restore x87 FPU, MMX and SSE state (includes MXCSR and XMM registers).
    fxrstor [rcx+OE_CONTEXT_FLOAT]

    ;; Subroutine epilogue
    mov rsp, rbp
    pop rbp
    ret

oe_restore_host_context ENDP

END

