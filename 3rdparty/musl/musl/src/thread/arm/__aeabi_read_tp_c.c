#include "pthread_impl.h"
#include <stdint.h>

__attribute__((__visibility__("hidden")))
void *__aeabi_read_tp_c(void)
{
	return (void *)((uintptr_t)__pthread_self()-8+sizeof(struct pthread));
}
