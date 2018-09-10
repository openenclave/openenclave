	.global __vfork
	.weak vfork
	.type __vfork,%function
	.type vfork,%function
__vfork:
vfork:
	svc 190
	jg  __syscall_ret
