#ifndef SHARED

#include <string.h>
#include "pthread_impl.h"

extern struct tls_image {
	void *image;
	size_t len, size, align;
} __static_tls;

#define T __static_tls

void __reset_tls()
{
	if (!T.size) return;
	pthread_t self = __pthread_self();
	memcpy(self->dtv[1], T.image, T.len);
	memset((char *)self->dtv[1]+T.len, 0, T.size-T.len);
}

#endif
