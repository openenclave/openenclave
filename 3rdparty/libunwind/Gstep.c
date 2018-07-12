#include "unwind_i.h"

#undef unw_step
#define unw_step _ULx86_64_step

// Wrapper for calling unw_step() throughout libunwind source. This 
// function checks whether the cursor is within the enclave image.
int __libunwind_unw_step(unw_cursor_t* cursor)
{
    struct dwarf_cursor* c = (struct dwarf_cursor*)cursor;

    // Check whether the [IP, IP+16) is within the enclave image.
    if (!oe_is_within_enclave((void*)c->ip, 16))
        return 0;

    // Check whether [cfa, cfa+1024) is within the enclave image.
    if (!oe_is_within_enclave((void*)c->cfa, 1024))
        return 0;

    return unw_step(cursor);
}

#include "Gstep.c.h"
