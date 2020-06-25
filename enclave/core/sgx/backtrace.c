// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/argv.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include "core_t.h"
#include "platform_t.h"

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

/* Safe implementation of backtrace.
 *
 * The original implementation used the ___builtin_return_address intrinsic.
 * The intrinsic however is unsafe and can crash if any function in the
 * call-stack does not preserve the stack-frame. This scenario can easily happen
 * if any function in the call-stack has been compiled with optimization, or is
 * a special function like global initializer.
 * This new implementation below safely walks up the call-stack, ensuring that
 * each potential-frame is not null and lies within the enclave.
 */
OE_NEVER_INLINE
int oe_backtrace_impl(void** start_frame, void** buffer, int size)
{
    void** frame = start_frame;
    // Upon entry to a function, rsp + 0 contains the return address.
    // Generally, the first thing that a function does upong entry is
    //     push %rbp
    // rbp is expected to contain the callee's frame pointer.
    // Thus after saving rbp,
    //     rsp + 0  (frame[0]) contains callee's frame pointer.
    //     rsp + 8  (frame[1]) contains return address (within the callee).
    //
    // However, the compiler may not always store the callee's frame-ptr in the
    // rbp register. Within optimizations enabled, the compiler could use rbp
    // just like other general-purpose register and hold some value rather than
    // the frame-pointer. While frame[1] always contains the return address,
    // frame[0] may not always contain the pointer to callee's stack frame.
    // To be on the safer-side, we always check that the values we access
    // while traversing the stack always lie within the enclave.
    int n = 0;
    while (n < size)
    {
        // Ensure that the current frame is safe to access.
        if (!_check_address(frame))
            break;

        // Ensure that the return address is valid.
        if (!_check_address(frame[1]))
            break;

        // Store address and move to previous frame.
        buffer[n++] = frame[1];
        frame = (void**)*frame;
    }

    return n;
}

/**
 * oe_backtrace itself must not appear in the backtrace. It ought to behave as
 * if it was inlined. To keep the implementation private, the function is
 * defined here (which rules out the ability to use compiler's inline keywords)
 * and its frame address is passed to oe_backtrace_impl. oe_backtrace_impl walks
 * the callstack starting at caller of the given frame. This ensures that
 * oe_backtrace is omitted from the backtrace. This scheme also works whether
 * the compiler emits a call or jmp instruction to call oe_backtrace_impl.
 */
int oe_backtrace(void** buffer, int size)
{
    return oe_backtrace_impl(__builtin_frame_address(0), buffer, size);
}

char** oe_backtrace_symbols_impl(
    void* const* buffer,
    int size,
    void* (*malloc_fcn)(size_t),
    void* (*realloc_fcn)(void*, size_t),
    void (*free_fcn)(void*))
{
    char** ret = NULL;
    void* symbols_buffer = NULL;
    const size_t SYMBOLS_BUFFER_SIZE = 4096;
    size_t symbols_buffer_size = SYMBOLS_BUFFER_SIZE;
    size_t symbols_buffer_size_out;
    uint32_t retval;
    char** argv = NULL;

    if (!buffer || size < 0)
        goto done;

    if (!(symbols_buffer = malloc_fcn(symbols_buffer_size)))
        goto done;

    /* First call might return OE_BUFFER_TOO_SMALL. */
    if (oe_sgx_backtrace_symbols_ocall(
            &retval,
            oe_get_enclave(),
            (const uint64_t*)buffer,
            (size_t)size,
            symbols_buffer,
            symbols_buffer_size,
            &symbols_buffer_size_out) != OE_OK)
    {
        goto done;
    }

    /* Second call uses buffer size returned by first call. */
    if ((oe_result_t)retval == OE_BUFFER_TOO_SMALL)
    {
        symbols_buffer_size = symbols_buffer_size_out;
        if (!(symbols_buffer =
                  realloc_fcn(symbols_buffer, symbols_buffer_size)))
            goto done;

        if (oe_sgx_backtrace_symbols_ocall(
                &retval,
                oe_get_enclave(),
                (const uint64_t*)buffer,
                (size_t)size,
                symbols_buffer,
                symbols_buffer_size,
                &symbols_buffer_size_out) != OE_OK)
        {
            goto done;
        }

        if ((oe_result_t)retval != OE_OK ||
            symbols_buffer_size_out != symbols_buffer_size)
        {
            goto done;
        }
    }
    else if ((oe_result_t)retval != OE_OK)
    {
        goto done;
    }

    /* Convert vector to array of strings. */
    if (oe_buffer_to_argv(
            symbols_buffer,
            symbols_buffer_size_out,
            &argv,
            (size_t)size,
            malloc_fcn,
            free_fcn) != OE_OK)
    {
        goto done;
    }

    ret = argv;
    argv = NULL;

done:

    if (symbols_buffer)
        free_fcn(symbols_buffer);

    if (argv)
        free_fcn(argv);

    return ret;
}

char** oe_backtrace_symbols(void* const* buffer, int size)
{
    /* Backtrace must use the allocator directly to bypass debug-malloc. */
    return oe_backtrace_symbols_impl(
        buffer,
        size,
        oe_allocator_malloc,
        oe_allocator_realloc,
        oe_allocator_free);
}

void oe_backtrace_symbols_free(char** ptr)
{
    /* Backtrace must use the allocator directly to bypass debug-malloc. */
    oe_allocator_free(ptr);
}
