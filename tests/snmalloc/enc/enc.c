// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include <stdlib.h>

#include "snmalloc_t.h"

// snmalloc requires at least 4K heap pages.
#define MIN_NUM_HEAP_PAGES (4 * 1024)

void enc_test_snmalloc_basic()
{
    // Make sure basic allocation/free works.
    void* p = malloc(1024);
    OE_TEST(p != NULL);
    free(p);

    // Make sure allocation fails as expected.
    p = malloc(1024 * 1024 * 1024);
    OE_TEST(p == NULL);
}

OE_SET_ENCLAVE_SGX(
    1,                  /* ProductID */
    1,                  /* SecurityVersion */
    true,               /* Debug */
    MIN_NUM_HEAP_PAGES, /* NumHeapPages */
    1024,               /* NumStackPages */
    2);                 /* NumTCS */

// If the default allocator (dlmalloc) was also linked into the enclave,
// the following definition would cause multiple definition errors.
// If no multiple definition errors are observed, then it means that
// the default allocator has been successfully replaced.
void* dlmalloc(size_t s)
{
    OE_UNUSED(s);
    return NULL;
}

void dlfree(void* ptr)
{
    OE_UNUSED(ptr);
}

void* dlcalloc(size_t nmemb, size_t size)
{
    OE_UNUSED(nmemb);
    OE_UNUSED(size);
    return NULL;
}

void* dlrealloc(void* ptr, size_t size)
{
    OE_UNUSED(ptr);
    OE_UNUSED(size);
    return NULL;
}

void* dlmemalign(size_t alignment, size_t size)
{
    OE_UNUSED(alignment);
    OE_UNUSED(size);
    return NULL;
}

int dlposix_memalign(void** memptr, size_t alignment, size_t size)
{
    OE_UNUSED(memptr);
    OE_UNUSED(alignment);
    OE_UNUSED(size);
    return 0;
}

size_t dlmalloc_usable_size(void* ptr)
{
    OE_UNUSED(ptr);
    return 0;
}
