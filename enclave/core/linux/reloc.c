// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include "../init.h"

/* Same layout as elf64_rela_t (see elf.h) */
typedef struct _oe_reloc
{
    uint64_t offset;
    uint64_t info;
    int64_t addend;
} oe_reloc_t;

/*
**==============================================================================
**
** oe_apply_relocations()
**
**     Apply symbol relocations from the relocation pages, whose content
**     was copied from the ELF file during loading. These relocations are
**     included in the enclave signature (MRENCLAVE).
**
**==============================================================================
*/

bool oe_apply_relocations(void)
{
    const oe_reloc_t* relocs = (const oe_reloc_t*)__oe_get_reloc_base();
    size_t nrelocs = __oe_get_reloc_size() / sizeof(oe_reloc_t);
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();

    for (size_t i = 0; i < nrelocs; i++)
    {
        const oe_reloc_t* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->offset == 0)
            break;

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->offset);

        (void)dest;

        /* Relocate the reference */
        *dest = (uint64_t)(baseaddr + p->addend);
    }

    return true;
}

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
**         (2) Invokes __cxa_atexit() passing it the destructor
**
**     Note that the FINI_ARRAY (used by oe_call_fini_functions) does not
**     contain any finalization functions for calling destructors. Instead
**     the __cxa_atexit() implementation must save the destructor functions
**     and invoke them on enclave termination.
**
**==============================================================================
*/

void oe_call_init_functions(void)
{
    void (**fn)(void);
    extern void (*__init_array_start)(void);
    extern void (*__init_array_end)(void);

    for (fn = &__init_array_start; fn < &__init_array_end; fn++)
    {
        (*fn)();
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
**     Destructors are passed to __cxa_atexit() by invoking functions in the
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
    void (**fn)(void);
    extern void (*__fini_array_start)(void);
    extern void (*__fini_array_end)(void);

    for (fn = &__fini_array_end - 1; fn >= &__fini_array_start; fn--)
    {
        (*fn)();
    }
}
