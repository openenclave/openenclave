;; Copyright (c) Open Enclave SDK contributors.
;; Licensed under the MIT License.

include ksamd64.inc

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


aep LABEL FAR
    ENCLU
    ud2

    BEGIN_EPILOGUE
    ret
NESTED_END OE_AEP, _TEXT$00


;;==============================================================================
;;
;; uint64_t OE_AEP_ADDRESS
;;
;;     The address of the ENCLU instruction is stored in this variable.
;;     If the OE_AEP function were to be used in code, the linker could create
;;     thunks that wrap the function. For example, when incremental linking is
;;     enabled, the linker on windows creates an entry in the ILT table for
;;     each function and uses that wherever the function is referenced.
;;     Thus OE_AEP would end up pointing to the thunk in the ILT which is not
;;     what we want. The OE_AEP_ADDRESS variable gives the precise location of
;;     the ENCLU instruction.
;;
;;==============================================================================
;;
;;
PUBLIC OE_AEP_ADDRESS; OE_AEP_ADDRESS
_DATA SEGMENT
OE_AEP_ADDRESS DQ aep
_DATA ENDS

END
