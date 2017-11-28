.global __set_thread_area
.type   __set_thread_area, @function
__set_thread_area:
	ldc r4, gbr
	rts
	 mov #0, r0
