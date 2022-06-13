// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>

// Function used by oeedger8r for allocating ocall buffers. This function can be
// optimized by allocating a buffer for making ocalls and pass it in to the
// ecall and making it available for use here.
//
// TODO: These are allocated inside the TA and subsequently marshalled by
//       oe_ocall via libutee. This means that the arguments structure is
//       needlessly copied twice in OP-TEE.
void* oe_allocate_ocall_buffer(size_t size)
{
    return oe_malloc(size);
}

// Function used by oeedger8r for freeing ocall buffers.
void oe_free_ocall_buffer(void* buffer)
{
    oe_free(buffer);
}

// TODO
void* oe_allocate_arena(size_t capacity)
{
    OE_UNUSED(capacity);
    return NULL;
}

// TODO
void oe_deallocate_arena(void* buffer)
{
    OE_UNUSED(buffer);
}
void* oe_host_calloc(size_t nmemb, size_t size)
{
    size_t total_size;
    if (oe_safe_mul_sizet(nmemb, size, &total_size) != OE_OK)
        return NULL;

    void* ptr = oe_host_malloc(total_size);

    if (ptr)
        oe_memset_s(ptr, nmemb * size, 0, nmemb * size);

    return ptr;
}

char* oe_host_strndup(const char* str, size_t n)
{
    char* p;
    size_t len;

    if (!str)
        return NULL;

    len = oe_strlen(str);

    if (n < len)
        len = n;

    /* Would be an integer overflow in the next statement. */
    if (len == OE_SIZE_MAX)
        return NULL;

    if (!(p = oe_host_malloc(len + 1)))
        return NULL;

    if (oe_memcpy_s(p, len + 1, str, len) != OE_OK)
        return NULL;

    p[len] = '\0';

    return p;
}
