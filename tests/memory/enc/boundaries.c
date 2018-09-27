// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include "../args.h"

#define BUFSIZE 1024
#define ITERS 1024

OE_ECALL void test_host_boundaries(void* args_)
{
    buffer* args = (buffer*)args_;
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    buffer buf = *args;
    OE_TEST(oe_is_outside_enclave(buf.buf, buf.size));
}

OE_ECALL void test_enclave_boundaries(void* args_)
{
    void* array[ITERS];
    for (int i = 0; i < ITERS; i++)
    {
        array[i] = malloc(BUFSIZE);
        OE_TEST(array[i] != NULL);
        OE_TEST(oe_is_within_enclave(array[i], BUFSIZE));
    }

    for (int i = 0; i < ITERS; i++)
        free(array[i]);
}

OE_ECALL void test_between_enclave_boundaries(void* args)
{
    boundary_args* bargs_ = (boundary_args*)args;
    if (!bargs_)
        return;

    /* Ensure host buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs_, sizeof(*bargs_)));

    boundary_args bargs = *bargs_;

    /* Ensure that buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs.host_stack.buf, bargs.host_stack.size));
    OE_TEST(oe_is_outside_enclave(bargs.host_heap.buf, bargs.host_heap.size));

    unsigned char* stackbuf = bargs.host_stack.buf;
    unsigned char* heapbuf = bargs.host_heap.buf;

    /* Verify host stack and heap pointers work. */
    for (int i = 0; i < bargs.host_stack.size; i++)
        OE_TEST(stackbuf[i] == 1);

    for (int i = 0; i < bargs.host_heap.size; i++)
        OE_TEST(heapbuf[i] == 2);

    /* Send two pointers. One from malloc (enclave memory) and
     * one from `oe_host_malloc` (host memory). */
    bargs.enclave_memory.buf = (unsigned char*)malloc(BUFSIZE);
    OE_TEST(bargs.enclave_memory.buf != NULL);
    OE_TEST(oe_is_within_enclave(bargs.enclave_memory.buf, BUFSIZE));
    bargs.enclave_memory.size = BUFSIZE;
    for (int i = 0; i < bargs.enclave_memory.size; i++)
        bargs.enclave_memory.buf[i] = 3;

    bargs.enclave_host_memory.buf = (unsigned char*)oe_host_malloc(BUFSIZE);
    OE_TEST(bargs.enclave_host_memory.buf != NULL);
    OE_TEST(oe_is_outside_enclave(bargs.enclave_host_memory.buf, BUFSIZE));
    bargs.enclave_host_memory.size = BUFSIZE;
    for (int i = 0; i < bargs.enclave_host_memory.size; i++)
        bargs.enclave_host_memory.buf[i] = 4;

    bargs_->enclave_memory = bargs.enclave_memory;
    bargs_->enclave_host_memory = bargs.enclave_host_memory;
}

OE_ECALL void try_input_enclave_pointer(void* args)
{
    boundary_args* bargs_ = (boundary_args*)args;
    if (!bargs_)
        return;

    /* Ensure host buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs_, sizeof(*bargs_)));

    boundary_args bargs = *bargs_;

    /* Ensure that enclave buffer is in the enclave. */
    OE_TEST(
        oe_is_within_enclave(
            bargs.enclave_memory.buf, bargs.enclave_memory.size));

    /* Verify enclave memory is unchanged. */
    for (int i = 0; i < bargs.enclave_memory.size; i++)
        OE_TEST(bargs.enclave_memory.buf[i] == 3);
}

OE_ECALL void free_boundary_memory(void* args)
{
    boundary_args* bargs_ = (boundary_args*)args;
    if (!bargs_)
        return;

    /* Ensure host buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs_, sizeof(*bargs_)));

    boundary_args bargs = *bargs_;

    /* Ensure that enclave buffer is in the enclave. */
    OE_TEST(
        oe_is_within_enclave(
            bargs.enclave_memory.buf, bargs.enclave_memory.size));

    free(bargs.enclave_memory.buf);
    oe_host_free(bargs.enclave_host_memory.buf);
}
