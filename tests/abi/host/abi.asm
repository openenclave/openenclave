;; Copyright (c) Open Enclave SDK contributors.
;; Licensed under the MIT License.
.CODE

PUBLIC oe_dummy_mmx_add
oe_dummy_mmx_add PROC

    pxor mm0, mm0
    paddd mm0, mm0
    ret

oe_dummy_mmx_add ENDP

PUBLIC oe_dummy_fpu_loads
oe_dummy_fpu_loads PROC

    fldz
    fldz
    fldz
    fldz
    fldz
    fldz
    fldz
    fldz
    ret

oe_dummy_fpu_loads ENDP

END
