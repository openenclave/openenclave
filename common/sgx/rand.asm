;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.
.CODE

PUBLIC oe_rdrand
oe_rdrand PROC

_rdrand_retry:
    rdrand rax
    jc _rdrand_epilogue
    pause
    jmp _rdrand_retry

_rdrand_epilogue:
    ret

oe_rdrand ENDP

PUBLIC oe_rdseed
oe_rdseed PROC

_rdseed_retry:
    rdseed rax
    jc _rdseed_epilogue
    pause
    jmp _rdseed_retry

_rdseed_epilogue:
    ret

oe_rdseed ENDP

END
