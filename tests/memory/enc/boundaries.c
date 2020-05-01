// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include "memory_t.h"

#define BUFSIZE 1024
#define ITERS 1024
#define OE_USED_HEAP 20584 /* Amount of heap consumed by OE. */

void test_host_boundaries(buffer buf)
{
    OE_TEST(oe_is_outside_enclave(buf.buf, buf.size));
}

void test_enclave_boundaries()
{
    void* array[ITERS] = {NULL};
    /* Calculate the upper bound of the heap. */
    size_t bound = __oe_get_heap_size() - OE_USED_HEAP;
    size_t allocated = 0;

    for (int i = 0; i < ITERS; i++)
    {
        if (allocated >= bound)
            break;

        array[i] = malloc(BUFSIZE);
        OE_TEST(array[i] != NULL);
        OE_TEST(oe_is_within_enclave(array[i], BUFSIZE));
        allocated += BUFSIZE;
    }

    for (int i = 0; i < ITERS; i++)
    {
        if (array[i])
            free(array[i]);
    }
}

void test_between_enclave_boundaries(
    buffer host_stack,
    buffer host_heap,
    buffer* enclave_memory,
    buffer* enclave_host_memory)
{
    /* Ensure that buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(host_stack.buf, host_stack.size));
    OE_TEST(oe_is_outside_enclave(host_heap.buf, host_heap.size));

    unsigned char* stackbuf = host_stack.buf;
    unsigned char* heapbuf = host_heap.buf;

    /* Verify host stack and heap pointers work. */
    for (size_t i = 0; i < host_stack.size; i++)
        OE_TEST(stackbuf[i] == 1);

    for (size_t i = 0; i < host_heap.size; i++)
        OE_TEST(heapbuf[i] == 2);

    /* Send two pointers. One from malloc (enclave memory) and
     * one from `oe_host_malloc` (host memory). */
    unsigned char* enclave_memory_local = (unsigned char*)malloc(BUFSIZE);
    OE_TEST(enclave_memory_local != NULL);
    OE_TEST(oe_is_within_enclave(enclave_memory_local, BUFSIZE));
    for (int i = 0; i < BUFSIZE; i++)
        enclave_memory_local[i] = 3;
    enclave_memory->buf = enclave_memory_local;
    enclave_memory->size = BUFSIZE;

    unsigned char* enclave_host_memory_local =
        (unsigned char*)oe_host_malloc(BUFSIZE);

    OE_TEST(enclave_host_memory_local != NULL);
    OE_TEST(oe_is_outside_enclave(enclave_host_memory_local, BUFSIZE));
    for (int i = 0; i < BUFSIZE; i++)
        enclave_host_memory_local[i] = 4;
    enclave_host_memory->buf = enclave_host_memory_local;
    enclave_host_memory->size = BUFSIZE;
}

void try_input_enclave_pointer(buffer enclave_memory)
{
    /* Ensure that enclave buffer is in the enclave. */
    OE_TEST(oe_is_within_enclave(enclave_memory.buf, enclave_memory.size));

    /* Verify enclave memory is unchanged. */
    for (size_t i = 0; i < enclave_memory.size; i++)
        OE_TEST(enclave_memory.buf[i] == 3);
}

void free_boundary_memory(buffer enclave_memory, buffer enclave_host_memory)
{
    /* Ensure that enclave buffer is in the enclave. */
    OE_TEST(oe_is_within_enclave(enclave_memory.buf, enclave_memory.size));

    free(enclave_memory.buf);
    oe_host_free(enclave_host_memory.buf);
}
