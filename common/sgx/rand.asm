;; Copyright (c) Microsoft Corporation. All rights reserved.
;; Licensed under the MIT License.
.CODE

PUBLIC oe_rdrand
oe_rdrand PROC
;; Subroutine Prologue
	push rbp     ;; Save the old base pointer value.
	mov rbp, rsp ;; Set the new base pointer value.
	sub rsp, 4   ;; Make room for one 4-byte local variable.

;; Subroutine Body
_rdrand_retry:
	rdrand rax
	jnc _rdrand_retry

;; Subroutine Epilogue
	mov rsp, rbp ;; Deallocate local variables
	pop rbp      ;; Restore the caller's base pointer value

	ret

oe_rdrand ENDP

END
