#include <stddef.h>
#include "pthread_impl.h"

void *__tls_get_addr(size_t *v)
{
	pthread_t self = __pthread_self();
#ifdef SHARED
	__attribute__((__visibility__("hidden")))
	void *__tls_get_new(size_t *);
	if (v[0]<=(size_t)self->dtv[0])
		return (char *)self->dtv[v[0]]+v[1];
	return __tls_get_new(v);
#else
	return (char *)self->dtv[1]+v[1];
#endif
}
