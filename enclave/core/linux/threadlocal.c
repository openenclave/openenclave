// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "threadlocal.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "../td.h"

/*
**==============================================================================
**
** Thread-Local Storage implementation.
**
**==============================================================================
*/

/**
 * There are two ways to create thread-local variables:
 *   1) GNU __thread keyword
 *      This can be applied only to POD types; i.e types that are initialized to
 *      a constant value, and don't have a constructor or destructor.
 *   2) C++11 thread_local keyword
 *      This can be applied to POD types, as well as to types with constructors
 *      and/or destructors.
 *
 * Thread-local variables that are explicitly initialized to constant values are
 * put in .tdata section. Thread-local variables that are not initialized or
 * that have complex initializers and/or destructors are put in .tbss section.
 * E.g:
 *      __thread int v1 = 56;           // Put in .tdata
 *      thread_local int v2 = 77;       // Put in .tdata
 *
 *      __thread int v3;                // Not initialized. Put in .tbss
 *      thread_local string s("Hello"); // Complex initializer. Put in .tbss
 *
 * .tdata section acts as a template for initializing the thread local-storage
 * of each thread since it contains the initial values of the variables.
 *
 * .tbss section just contains total size of the variables in .tbss section.
 *
 * In order to initialize the thread-local storage for a thread, the .tdata
 * section must be copied over to the correct offset from the fs register.
 * Also the space for .tbss section must be allocated and initialized to zeros.
 * The typical layout is as follows:
 *
 *                          +----------------------------+
 *                   FS[0]  | Self pointer (value of FS) |
 *                          +----------------------------+
 *                   FS[-1] |  tbss variables            |
 *                          |  This section is zero      |
 *                          |  initialized. Section size |
 *                          |  is aligned according to   |
 *                          |  alignment specified in elf|
 *  FS[-tbss start offset]  +----------------------------+
 *                          |  tdata variables           |
 *                          |  The contents of .tdata    |
 *                          |  template is copied here.  |
 *                          |  Section size is aligned   |
 *                          |  according to alignment    |
 *                          | specified in elf.          |
 *  FS[-tdata start offset] +----------------------------+   <- tls data start
 *
 * In x86-64, the FS register is used to access thread-local data.
 * Just like GS[0], FS[0] is a self pointer and must contain the value of FS.
 * Note that negative indexing is used with FS. Thus the thread-local variables
 * lie before FS.
 *
 * Both .tdata and .tbss sections have alignment. The alignment must be used to
 * adjust their specified size values.
 * Consider
 *        __thread char chars[6];  // 6 bytes
 *        __thread int g = 45;     // 4 bytes
 * Assume that g is the first variable in the .tdata section and that
 * the .tdata section size is 10 bytes and that the alignment is 4 bytes.
 * Then the aligned size of the section is 12 bytes and the compiler
 * uses the offset %FS:-12 to access g instead of %FS:-10.
 *
 * Note: Both .tdata and .tbss sections can have different alignments.
 * In such cases, the larger of the alignments is used to align both the
 * sections. In x86-64, as observed by doing 'objdump -h' on an elf file, all
 * sections are aligned to a power of two. This implies that the alignment of
 * one section must be a multiple of the alignment of the other.
 *
 * Initializing variables with complex initializers:
 * Consider
 *       thread_local int x = random();
 *       int foo() { return x; }
 *
 * This variable is put in .tbss section.
 * At a high-level, the compiler transforms the access of x to call to
 * a thread-local dynamic initializer of x.
 *       thread_local int x;   // Put in .tbss
 *       thread_local bool x_initialized; // Introduced by compiler to keep
 *                                        // track of x's initialization.
 *       int foo()
 *       {
 *          if (!x_initialized)
 *              dynamic_initializer_for_x();
 *          return x;
 *       }
 * The compiler uses an extra thread-local variable to check if x has been
 * initialized or not. If x has not been initialized, then the initializer
 * for x is called. With optimizations enabled, many if not all, of
 * these function calls get inlined and optimized.
 *
 * Variables with complex destructors:
 * Consider
 *       thread_local my_class x;
 * In the thread-local dynamic initializer for x, immediately after x has been
 * initialized, a call is made to the ABI function __cxa_thread_atexit:
 *       __cxa_thread_atexit(&my_class::~myclass, &x)
 * This allows the runtime system to invoke the destructor on the object when
 * the thread shutsdown.
 *
 * Note:
 * There are different thread-local models (see -ftls-model compiler option)
 * and the compiler normally emits a call to __tls_get_addr function to
 * access thread local variables. Since the enclave is linked as the main
 * executable, the linker performs *guaranteed optimizations* to remove the
 * calls to __tls_get_addr and to reduce thread-local variable access to simple
 * FS register offsets. To handle dynamically loaded modules we need to
 * implement __tls_get_addr.
 * For complete reference see: Elf Handling for Thread-Local Storage
 */
static volatile uint64_t _tdata_rva = 0;
static volatile uint64_t _tdata_size = 0;
static volatile uint64_t _tdata_align = 1;

static volatile uint64_t _tbss_size = 0;
static volatile uint64_t _tbss_align = 1;

/**
 * Get the address of the FS segment given a thread data object.
 * Currently FS is assumed to exist one page after the thread data.
 * This needs to be made more flexible, taking into account the
 * actual size of the tls data.
 */
static uint8_t* _get_fs_from_td(td_t* td)
{
    // TODO: Make this flexible
    uint8_t* fs = (uint8_t*)td + 1 * OE_PAGE_SIZE;
    return fs;
}

/**
 * Return aligned size.
 */
static uint64_t _get_aligned_size(uint64_t size, uint64_t align)
{
    return align ? oe_round_up_to_multiple(size, align) : size;
}

/**
 * Return pointer to start of tls data.
 *    tls-data-start = %FS - (aligned .tdata size + aligned .tbss size)
 */
static uint8_t* _get_thread_local_data_start(td_t* td)
{
    // Check if this enclave has thread-local data.
    if (!_tdata_size && !_tbss_size)
        return NULL;

    uint8_t* fs = _get_fs_from_td(td);
    uint64_t alignment = 0;

    // Alignments must be non-zero.
    if (!_tdata_align || !_tbss_align)
        oe_abort();

    // Choose the largest of the two alignments to align both the sections.
    // Assert that one alignment is a multiple of the other.
    if (_tdata_align >= _tbss_align)
    {
        alignment = _tdata_align;
        if (alignment % _tbss_align)
            oe_abort();
    }
    else
    {
        alignment = _tbss_align;
        if (alignment % _tdata_align)
            oe_abort();
    }

    // Alignment must be a power of two.
    if (alignment & (alignment - 1))
        oe_abort();

    // Align both the sections.
    fs -= _get_aligned_size(_tbss_size, alignment);
    fs -= _get_aligned_size(_tdata_size, alignment);

    return fs;
}

/**
 * Initialize the thread-local section for a given thread.
 * This must be called immediately after td itself is initialized.
 */
oe_result_t oe_thread_local_init(td_t* td)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* tls_start = _get_thread_local_data_start(td);

    if (td == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (tls_start)
    {
        // Fetch the tls data start for the thread.
        uint8_t* fs = _get_fs_from_td(td);

        // Set the self pointer.
        *(void**)fs = fs;

        uint64_t tls_data_size = (uint64_t)(fs - tls_start);

        // Initialize the tls data to zero.
        oe_memset_s(tls_start, tls_data_size, 0, tls_data_size);

        // Fetch the .tdata template.
        void* tdata = (uint8_t*)__oe_get_enclave_base() + _tdata_rva;

        // Copy the template
        oe_memcpy_s(tls_start, _tdata_size, tdata, _tdata_size);
    }

    result = OE_OK;
done:
    return result;
}

/**
 * Register a destructor to be called on the given object when the
 * thread exits. This call is emitted by the compiler.
 */
void __cxa_thread_atexit(void (*destructor)(void*), void* object)
{
    td_t* td = oe_get_td();
    oe_tls_atexit_t item = {destructor, object};

    td->num_tls_atexit_functions++;

    // TODO: What happens if realloc fails?
    td->tls_atexit_functions = oe_realloc(
        td->tls_atexit_functions,
        sizeof(oe_tls_atexit_t) * td->num_tls_atexit_functions);

    td->tls_atexit_functions[td->num_tls_atexit_functions - 1] = item;
}

/**
 * Cleanup the thread-local section for a given thread.
 * This must be called *before* the td itself is cleaned up.
 */
oe_result_t oe_thread_local_cleanup(td_t* td)
{
    /* Call tls atexit functions in reverse order*/
    if (td->tls_atexit_functions)
    {
        for (uint64_t i = td->num_tls_atexit_functions; i > 0; --i)
        {
            td->tls_atexit_functions[i - 1].destructor(
                td->tls_atexit_functions[i - 1].object);
        }

        // Free the allocated at exit buffer.
        oe_free(td->tls_atexit_functions);
        td->tls_atexit_functions = NULL;
        td->num_tls_atexit_functions = 0;
    }

    /* Clear tls section */
    uint8_t* fs = _get_fs_from_td(td);
    uint8_t* tls_start = _get_thread_local_data_start(td);
    oe_memset_s(tls_start, (uint64_t)(fs - tls_start), 0, 0);

    return OE_OK;
}
