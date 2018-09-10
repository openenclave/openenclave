#define START "_start"
#define _dlstart_c _start_c
#include "../ldso/dlstart.c"

int main();
void _init() __attribute__((weak));
void _fini() __attribute__((weak));
_Noreturn int __libc_start_main(int (*)(), int, char **,
	void (*)(), void(*)(), void(*)());

__attribute__((__visibility__("hidden")))
_Noreturn void __dls2(unsigned char *base, size_t *sp)
{
	__libc_start_main(main, *sp, (void *)(sp+1), _init, _fini, 0);
}
