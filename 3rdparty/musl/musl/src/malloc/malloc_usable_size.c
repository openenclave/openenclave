#include <malloc.h>

void *(*const __realloc_dep)(void *, size_t) = realloc;

struct chunk {
	size_t psize, csize;
	struct chunk *next, *prev;
};

#define OVERHEAD (2*sizeof(size_t))
#define CHUNK_SIZE(c) ((c)->csize & -2)
#define MEM_TO_CHUNK(p) (struct chunk *)((char *)(p) - OVERHEAD)

size_t malloc_usable_size(void *p)
{
	return p ? CHUNK_SIZE(MEM_TO_CHUNK(p)) - OVERHEAD : 0;
}
