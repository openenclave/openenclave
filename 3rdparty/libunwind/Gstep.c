// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wsign-conversion"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#endif

#include <libunwind.h>
#include <openenclave/enclave.h>
#include "unwind_i.h"

#undef unw_step
#define unw_step _ULx86_64_step

extern int _ULx86_64_step(unw_cursor_t* cursor);

// Wrapper for calling unw_step() throughout libunwind source. This
// function checks whether the cursor is within the enclave image.
int __libunwind_unw_step(unw_cursor_t* cursor)
{
    struct dwarf_cursor* c = (struct dwarf_cursor*)cursor;

    // Only enforce this check for local address spaces (which enclaves use).
    // Otherwise the remote libunwind tests fail.
    if (c->as == unw_local_addr_space)
    {
        // Check whether the [IP, IP+16) is within the enclave image.
        if (!oe_is_within_enclave((void*)c->ip, 16))
            return 0;

        // Check whether [cfa, cfa+1024) is within the enclave image.
        if (!oe_is_within_enclave((void*)c->cfa, 1024))
            return 0;
    }

    return unw_step(cursor);
}

#include "Gstep.inc"

/* Added when porting to libunwind 1.3 to suppress unresolved symbol */
void* __gcc_personality_v0;
