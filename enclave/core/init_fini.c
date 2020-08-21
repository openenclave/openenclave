// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "init_fini.h"
#include <openenclave/internal/globals.h>

/*
**==============================================================================
**
** oe_call_init_functions()
**
**     Call all global initialization functions. The compiler generates an
**     array of initialization functions which it places in one of the dynamic
**     program segments (where elf64_phdr_t.type == PT_DYNAMIC). This segment
**     contains two elf64_dyn structures whose tags are given as follows:
**
**         elf64_dyn.d_tag == DT_INIT_ARRAY
**         elf64_dyn.d_tag == DT_INIT_ARRAYSZ
**
**     The first (INIT_ARRAY) is an array of function pointers to global
**     initializers. The second (INIT_ARRAYSZ) is the size of that array in
**     bytes (not the number of functions). When the compiler encounters the
**     following extern declarations in user object code
**
**         extern void (*__init_array_start)(void);
**         extern void (*__init_array_end)(void);
**
**     it generates corresponding definitions that refer to INIT_ARRAY and
**     INIT_ARRAYSZ as follows:
**
**         __init_array_start = INIT_ARRAY
**         __init_array_end = INIT_ARRAY + DT_INIT_ARRAYSZ;
**
**     Initialization functions are of two types:
**
**         (1) C functions tagged with __attribute__(constructor)
**         (2) C++ global constructors
**
**     oe_call_init_functions() invokes all functions in this array from start
**     to finish.
**
**     Here are some notes on initialization functions that relate to C++
**     construction. There is typically one initialization function per
**     compilation unit, so that calling that function will invoke all global
**     constructors for that compilation unit. Further, for each object
**     being constructed, the compiler generates a function that:
**
**         (1) Invokes the constructor
**         (2) Invokes oe_cxa_atexit() passing it the destructor
**
**     Note that the FINI_ARRAY (used by oe_call_fini_functions) does not
**     contain any finalization functions for calling destructors. Instead
**     the oe_cxa_atexit() implementation must save the destructor functions
**     and invoke them on enclave termination.
**
**==============================================================================
*/

void oe_call_init_functions(void)
{
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();

    /* Call the start functions of each module in order. */
    for (size_t i = 0; i < OE_MAX_NUM_MODULES; ++i)
    {
        const oe_module_link_info_t* link_info = &oe_linked_modules[i];

        /* Check if module is valid. Relocated RVA should be non-zero. */
        if (link_info->init_array_rva && link_info->init_array_size)
        {
            uint64_t init_array_start =
                (uint64_t)baseaddr + link_info->init_array_rva;

            uint64_t init_array_end =
                init_array_start + link_info->init_array_size;

            for (uint64_t fn = init_array_start; fn < init_array_end;
                 fn += sizeof(void*))
            {
                void (**init)(void) = (void (**)(void))fn;
                (*init)();
            }
        }
    }
}

/*
**==============================================================================
**
** oe_call_fini_functions()
**
**     Call all global finalization functions. The compiler generates an array
**     of finalization functions which it places in one of the dynamic program
**     segments (where elf64_phdr_t.type == PT_DYNAMIC). This segment contains
**     two elf64_dyn structures whose tags are given as follows:
**
**         elf64_dyn.d_tag == DT_FINI_ARRAY
**         elf64_dyn.d_tag == DT_FINI_ARRAYSZ
**
**     The first (FINI_ARRAY) is an array of function pointers to the
**     finalizers. The second (FINI_ARRAYSZ) is the size of that array in
**     bytes (not the number of functions). When the compiler encounters the
**     following extern declarations in user object code:
**
**         extern void (*__fini_array_start)(void);
**         extern void (*__fini_array_end)(void);
**
**     it generates corresponding definitions that refer to FINI_ARRAY and
**     FINI_ARRAYSZ as follows:
**
**         __fini_array_start = FINI_ARRAY
**         __fini_array_end = FINI_ARRAY + DT_FINI_ARRAYSZ;
**
**     Finalization functions are of one type of interest:
**
**         (1) C functions tagged with __attribute__(destructor)
**
**     Note that global C++ destructors are not referenced by the FINI_ARRAY.
**     Destructors are passed to oe_cxa_atexit() by invoking functions in the
**     INIT_ARRAY (see oe_call_init_functions() for more information).
**
**     oe_call_fini_functions() invokes all functions in this array from finish
**     to start (reverse order).
**
**     For more information on C++ destruction invocation, see the
**     "Itanium C++ ABI".
**
**==============================================================================
*/

void oe_call_fini_functions(void)
{
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();

    /* Call the finalization functions of each module in reverse order. */
    for (size_t i = OE_MAX_NUM_MODULES - 1; i < OE_MAX_NUM_MODULES; --i)
    {
        const oe_module_link_info_t* link_info = &oe_linked_modules[i];

        /* Check if module is valid. Relocated RVA should be non-zero. */
        if (link_info->fini_array_rva && link_info->fini_array_size)
        {
            uint64_t fini_array_start =
                (uint64_t)baseaddr + link_info->fini_array_rva;

            uint64_t fini_array_end =
                fini_array_start + link_info->fini_array_size;

            for (uint64_t fn = fini_array_start; fn < fini_array_end;
                 fn += sizeof(void*))
            {
                void (**fini)(void) = (void (**)(void))fn;
                (*fini)();
            }
        }
    }
}
