// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "threadlocal.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/allocator.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include "td.h"

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
 * For complete reference see: Elf Handling for Thread-Local Storage.
 *
 * The thread-locals described above follow the "Local-Exec" tls model.
 * They produce the most efficient opcodes for accessing thread-local variables.
 *
 * The thread-locals described below follow the "Initial-Exec" tls model.
 * They are also very efficient, but require and extra memory dereference
 * compared to the "Local-Exec" model.
 *
 * The other two models - "Local-Dynamic" and "Global-Dynamic" are currently
 * not supported since they are more applicable to a multi-module enclaves
 * scenario (i.e many shared libraries loaded into a single enclave.).
 * Using those tls-model, via a combination of compiler and linker flags,
 * would result in a link error since the __tls_get_addr function is not
 * defined.
 *
 * ****************************************************************************
 * Exported thread-locals and shared-libraries:
 *
 * When thread-local variables are exported (via visibility=default), then the
 * linker does not optimize the access of a thread-local variable to a constant
 * offset from the FS register. Instead, for each thread-local variable,
 * another variable is introduced varname@tpoff that contains the offset for
 * the thread local variable. The offset value for varname@tpoff is expected to
 * be filled up by the dynamic linker/loader.
 * Consider,
 *         __attribute__((visibility=default)) __thread int x;
 *         int foo() { return x; }
 *
 * This results in the following code to access x
 *     foo:
 *         ...
 *         mov %FS:0, %rax            // Fetch the address of the FS segment
 *         add x@tpoff(%rip), %rax    // Fetch offset for x from the
 *                                    // relocation entry x@tpoff and add it to
 *                                    // FS
 *         mov (%rax), rax            // Fetch value of x
 *
 * Each @tpoff variable results in a relocation entry of the type
 * R_X86_64_TPOFF64. The relocation entry contains enough information to fill
 * the value of the @tpoff variable.
 * R_X86_64_TPOFF64 relocation info contains the following fields:
 *
 *    r_offset = relative address of the corresponding tpoff variable
 *    r_info.relocation_type = R_X86_64_TPOFF64
 *    r_info.symbol = index of symbol in the .dynsym section.
 *    r_addend = 0
 *
 * The value (st_value) of the symbol in the .dynsym section contains the offset
 * to the thread-local variable from the *start* of the thread-local section.
 * Thus:
 *    &x = tls-start + symbol sh_value.
 *
 * Since the compiler emits code relative to the end of the section (i.e using
 * FS), the tpoff is computed via the formula:
 *     tpoff = FS - (tls-start + sh-value).
 *
 * Thus, performing relocations for thread-local variables involves setting the
 * value of the corresponding tpoff variables to the offset from the FS register
 * value.
 *
 * To avoid looking up symbols within the enclave (symbols are not available)
 * the loader fetches the symbol's sh-value and stores it in the r_addend field
 * (r_added field is otherwise zero for R_X86_64_TPOFF64).
 */
static volatile uint64_t _tdata_rva = 0;
static volatile uint64_t _tdata_size = 0;
static volatile uint64_t _tdata_align = 1;

static volatile uint64_t _tbss_size = 0;
static volatile uint64_t _tbss_align = 1;

// Number of thread-local relocations.
static volatile bool _thread_locals_relocated = false;

// TODO: Make this flexible in case more than one page of thread local storage
// need to allocate.

/* The thread data (td) object is always populated at the start of the
   FS segment, so this method just returns the address of the td.
*/
static uint8_t* _get_fs_from_td(oe_sgx_td_t* td)
{
    uint8_t* fs = (uint8_t*)td;
    return fs;
}

/**
 * Return aligned size.
 */
static uint64_t _get_aligned_size(uint64_t size, uint64_t align)
{
    return align ? oe_round_up_to_multiple(size, align) : size;
}

/*
 * Call oe_allocator_init with heap start and end addresses.
 */
static void _call_oe_allocator_init(void)
{
    oe_allocator_init((void*)__oe_get_heap_base(), (void*)__oe_get_heap_end());
}

/*
 * Initialize the allocator using oe_once.
 */
static void _initialize_allocator(void)
{
    static oe_once_t _once = OE_ONCE_INITIALIZER;
    oe_once(&_once, _call_oe_allocator_init);
}

/**
 * Return pointer to start of tls data.
 *    tls-data-start = %FS - (aligned .tdata size + aligned .tbss size)
 */
static uint8_t* _get_thread_local_data_start(oe_sgx_td_t* td)
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
oe_result_t oe_thread_local_init(oe_sgx_td_t* td)
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

        // Perform thread-local relocations.
        if (!_thread_locals_relocated)
        {
            // Note: For an enclave, thread-local relocations always set the
            // value of the tpoff variables to a computed constant value. Hence
            // this is inherently thread-safe and also can be called multiple
            // times.
            const elf64_rela_t* relocs =
                (const elf64_rela_t*)__oe_get_reloc_base();
            size_t nrelocs = __oe_get_reloc_size() / sizeof(elf64_rela_t);
            const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();

            for (size_t i = 0; i < nrelocs; i++)
            {
                const elf64_rela_t* p = &relocs[i];

                // If zero-padded bytes reached
                if (p->r_offset == 0)
                    break;

                if (ELF64_R_TYPE(p->r_info) == R_X86_64_TPOFF64)
                {
                    // Compute address of tpoff variable
                    int64_t* tpoff = (int64_t*)(baseaddr + p->r_offset);

                    // Set tpoff to the offset value relative to FS
                    *tpoff = (tls_start + p->r_addend - fs);
                }
            }

            _thread_locals_relocated = true;
        }

        {
            static bool _allocator_initialized = false;
            bool initialized = _allocator_initialized;
            OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
            if (!initialized)
            {
                /* Initialize the allocator */
                OE_ATOMIC_MEMORY_BARRIER_RELEASE();
                _allocator_initialized = true;
            }
        }

        // To properly initialize the allocator, oe_allocator_init must first be
        // called with the heap start and end addresses. The allocator can
        // initialize itself during this call. Then, every time an enclave
        // thread is created, oe_allocator_thread_init will be called to allow
        // the allocator to perform per thread initialization.
        // It would seem that _handle_init_enclave is the natural place to call
        // oe_allocator_init to initialize the enclave and here
        // (oe_thread_local_init) is the natural place to call
        // oe_allocator_thread_init to perform thread-specific allocator
        // initialization. However, currently, td_init and hence
        // oe_thread_local_init is called *before* _handle_init_enclave is
        // called. This results in incorrect order of the allocator callbacks.
        // Therefore, we call oe_allocator_init here (via oe_once)
        // and then call oe_allocator_thread_init.
        _initialize_allocator();
        oe_allocator_thread_init();
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
    oe_sgx_td_t* td = oe_sgx_get_td();

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
oe_result_t oe_thread_local_cleanup(oe_sgx_td_t* td)
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

    /* Clear tls section if it exists */
    uint8_t* fs = _get_fs_from_td(td);
    uint8_t* tls_start = _get_thread_local_data_start(td);
    if (tls_start)
    {
        oe_allocator_thread_cleanup();
        oe_memset_s(tls_start, (uint64_t)(fs - tls_start), 0, 0);
    }

    return OE_OK;
}
