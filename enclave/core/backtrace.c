// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>

#if defined(__INTEL_COMPILER)
#error "optimized __builtin_return_address() not supported by Intel compiler"
#endif

/* Return null if address is outside of the enclave; else return ptr. */
const void* _check_address(const void* ptr)
{
    if (!oe_is_within_enclave(ptr, sizeof(uint64_t)))
        return NULL;

    return ptr;
}

int oe_backtrace(void** buffer, int size)
{
    const void* addrs[OE_BACKTRACE_MAX];
    int n = 0;
    int i;

    // It isn't possible to use iteration here since __builtin_return_address()
    // must take a constant argument. Also, the depth is limited to
    // OE_BACKTRACE_MAX.
    do
    {
        if (!(addrs[n] = _check_address(__builtin_return_address(0))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(1))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(2))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(3))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(4))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(5))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(6))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(7))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(8))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(9))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(10))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(11))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(12))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(13))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(14))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(15))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(16))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(17))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(18))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(19))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(20))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(21))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(22))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(23))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(24))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(25))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(26))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(27))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(28))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(29))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(30))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(31))))
            break;

        OE_STATIC_ASSERT(OE_BACKTRACE_MAX == 32);

    } while (0);

    /* If the caller's buffer is too small */
    if (n > size)
        n = size;

    /* Copy addresses to caller's buffer */
    if (buffer)
    {
        for (i = 0; i < n; i++)
            buffer[i] = (void*)addrs[i];
    }

    return n;
}

char** oe_backtrace_symbols(void* const* buffer, int size)
{
    char** ret = NULL;
    oe_backtrace_symbols_args_t* args = NULL;

    if (!buffer || size > OE_BACKTRACE_MAX)
        goto done;

    if (!(args = oe_host_malloc(sizeof(oe_backtrace_symbols_args_t))))
        goto done;

    oe_memcpy(args->buffer, buffer, sizeof(void*) * size);
    args->size = size;
    args->ret = NULL;

    if (oe_ocall(OE_OCALL_BACKTRACE_SYMBOLS, (uint64_t)args, NULL) != OE_OK)
        goto done;

    ret = args->ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
}

oe_result_t oe_print_backtrace(void)
{
    oe_result_t result = OE_UNEXPECTED;
    void* buffer[OE_BACKTRACE_MAX];
    size_t size;
    char** syms = NULL;

    if ((size = oe_backtrace(buffer, OE_BACKTRACE_MAX)) <= 0)
        OE_RAISE(OE_FAILURE);

    if (!(syms = oe_backtrace_symbols(buffer, size)))
        OE_RAISE(OE_FAILURE);

    oe_host_printf("=== backtrace:\n");

    for (size_t i = 0; i < size; i++)
        oe_host_printf("%s(): %p\n", syms[i], buffer[i]);

    oe_host_printf("\n");
    oe_host_free(syms);

    result = OE_OK;

done:
    return result;
}
