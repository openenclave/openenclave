// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int debugger_test;
extern int is_module_init;

void notify_module_done_wrapper();
int oe_sgx_get_additional_host_entropy(uint8_t* data, size_t size);

__attribute__((constructor)) void init_module()
{
    if (!debugger_test)
        is_module_init = 1;
}

__attribute__((destructor)) void fini_module()
{
    if (!debugger_test)
        notify_module_done_wrapper();
}

int square(volatile int a)
{
    volatile int r = 0;
    if (!debugger_test)
        r = a * a;
    return r;
}

int k = 500;

int add_with_constant(volatile int a, volatile int b)
{
    volatile int t = 0;
    if (!debugger_test)
        t = a + b + k;
    else
        t = -1;
    return t;
}

#define TEST_SYMBOL(name)                 \
    do                                    \
    {                                     \
        volatile void* ptr = (void*)name; \
        (void)ptr;                        \
    } while (0)

int test_libc_symbols()
{
    TEST_SYMBOL(memcmp);
    TEST_SYMBOL(memcpy);
    TEST_SYMBOL(memmove);
    TEST_SYMBOL(memset);
    TEST_SYMBOL(oe_sgx_get_additional_host_entropy);
    TEST_SYMBOL(pthread_mutex_destroy);
    TEST_SYMBOL(pthread_mutex_init);
    TEST_SYMBOL(pthread_mutex_lock);
    TEST_SYMBOL(pthread_mutex_unlock);
    TEST_SYMBOL(posix_memalign);
    TEST_SYMBOL(free);
    TEST_SYMBOL(qsort);

    /* The size of pthread_mutex_t is required to be 40 to be
     * compatible with musl and glibc. */
    if (sizeof(pthread_mutex_t) != 40)
        return 0;

    uint8_t data[16];
    if (!oe_sgx_get_additional_host_entropy(data, 16))
        return 0;

    return 1;
}
