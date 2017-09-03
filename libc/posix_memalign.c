#include <stdlib.h>

extern int dlposix_memalign(void **memptr, size_t alignment, size_t size);

extern int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    return dlposix_memalign(memptr, alignment, size);
}
