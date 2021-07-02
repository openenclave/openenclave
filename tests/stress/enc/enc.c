// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/print.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/tests.h>
#include <malloc.h>
#include "stress_t.h"

static int rcv = 0;

void do_ecall(int arg)
{
    // almost do nothing
    rcv = arg + 1;
}

static void set_buffer(unsigned long* buffer, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++)
        buffer[i] = i;
}

static void get_buffer(unsigned long* buffer, size_t start, size_t end)
{
    for (size_t i = start; i < end; i++)
        OE_TEST(buffer[i] == i);
}

void do_malloc(int memory_size)
{
    unsigned long* ptr = (unsigned long*)malloc((unsigned long)memory_size * sizeof(unsigned long));
    OE_TEST(ptr != NULL);
    set_buffer(ptr, 0, (unsigned long)memory_size);
    get_buffer(ptr, 0, (unsigned long)memory_size);
    free(ptr);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    1);   /* TCSCount */
