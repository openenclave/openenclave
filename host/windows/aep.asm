;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.

include ksamd64.inc

;; ThreadBinding_tcs EQU 0h
;; ENCLU_ERESUME EQU 3h

;;==============================================================================
;;
;; void OE_AEP(void)
;;
;;     Asynchronous Exception Pointer (AEP) function that handles exceptions
;;     and interrupts from an enclave. A pointer to this function is passed
;;     to the EENTER instruction and this function. This implementation resumes
;;     execution of the enclave (ERESUME).
;;
;;     This function must not use or modify the stack, else it could overwrite
;;     the host stack region used by enclave host stack allocaiton routines.
;;
;;==============================================================================


NESTED_ENTRY OE_AEP, _TEXT$00
    END_PROLOGUE

aep:
    ;; ATTN: port not complete but these are probably not needed
    ;; mov rax, ENCLU_ERESUME
    ;; mov rbx, fs:[ThreadBinding_tcs]
    ;; lea rcx, aep
    ;; mov rdx, 0
    ENCLU
    ud2

    BEGIN_EPILOGUE
    ret
NESTED_END OE_AEP, _TEXT$00

END
