// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "init_fini.h"

#if defined(OE_USE_DSO_DYNAMIC_BINDING)
#include <openenclave/internal/dynlink.h>
#include <openenclave/internal/globals.h>

static dso_t* fini_head;

static void do_init_fini(dso_t* p)
{
    /* NOTE: OE expects do_init_fini to be invoked only once on enclave
     * init and elides the locking around the setting of fini_head.
     * If dynamic loading is permitted in global constructors, then
     * the locking check would need to be added */

    fini_head = NULL;
    size_t dyn[DYN_CNT];

    for (; p; p = p->prev)
    {
        if (p->constructed)
            continue;
        p->constructed = 1;
        decode_vec(p->dynv, dyn, DYN_CNT);
        if (dyn[0] & ((1 << DT_FINI) | (1 << DT_FINI_ARRAY)))
        {
            p->fini_next = fini_head;
            fini_head = p;
        }

        /* MUSL supports legacy init/fini functions which OE
         * does not, but could be added with: */
        // if ((dyn[0] & (1 << DT_INIT)) && dyn[DT_INIT])
        //     fpaddr(p, dyn[DT_INIT])();

        if (dyn[0] & (1 << DT_INIT_ARRAY))
        {
            size_t n = dyn[DT_INIT_ARRAYSZ] / sizeof(size_t);
            size_t* fn = laddr(p, dyn[DT_INIT_ARRAY]);
            while (n--)
                ((void (*)(void)) * fn++)();
        }
    }
}
#endif

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
#if defined(OE_USE_DSO_DYNAMIC_BINDING)
    /* Walk the DSO in reverse order to perform initialization */
    dso_t* dso_head = (dso_t*)oe_get_dso_head();
    dso_t* dso_tail = dso_head;
    for (; dso_tail; dso_tail = dso_tail->next)
        if (!dso_tail->next)
            break;

    do_init_fini(dso_tail);
#else
    void (**fn)(void);
    extern void (*__init_array_start)(void);
    extern void (*__init_array_end)(void);
    for (fn = &__init_array_start; fn < &__init_array_end; fn++)
    {
        (*fn)();
    }
#endif
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
#if defined(OE_USE_DSO_DYNAMIC_BINDING)
    // NOTE: Equivalent of MUSL __libc_exit_fini()
    dso_t* p;
    size_t dyn[DYN_CNT];
    for (p = fini_head; p; p = p->fini_next)
    {
        if (!p->constructed)
            continue;
        decode_vec(p->dynv, dyn, DYN_CNT);
        if (dyn[0] & (1 << DT_FINI_ARRAY))
        {
            size_t n = dyn[DT_FINI_ARRAYSZ] / sizeof(size_t);
            size_t* fn = (size_t*)laddr(p, dyn[DT_FINI_ARRAY]) + n;
            while (n--)
                ((void (*)(void)) * --fn)();
        }
        /* MUSL supports legacy init/fini functions which OE
         * does not, but could be added with: */
        // if ((dyn[0] & (1 << DT_FINI)) && dyn[DT_FINI])
        //     fpaddr(p, dyn[DT_FINI])();
    }
#else
    void (**fn)(void);
    extern void (*__fini_array_start)(void);
    extern void (*__fini_array_end)(void);
    for (fn = &__fini_array_end - 1; fn >= &__fini_array_start; fn--)
    {
        (*fn)();
    }
#endif
}
