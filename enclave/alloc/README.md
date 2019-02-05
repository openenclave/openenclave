This directory contains the default OE allocator, which defines the following
functions.

```
void oe_allocator_startup(void)
void oe_allocator_teardown(void)
void* oe_allocator_malloc(size_t size)
void* oe_allocator_calloc(size_t nmemb, size_t size)
void* oe_allocator_realloc(void* ptr, size_t size)
void* oe_allocator_memalign(size_t alignment, size_t size)
int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size)
void oe_allocator_free(void* ptr)
int oe_allocator_get_stats(oe_malloc_stats_t* stats)
```
