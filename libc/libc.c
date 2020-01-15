// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "libc.h"

#include <openenclave/internal/defs.h>

struct __libc __libc;

size_t __hwcap;
size_t __sysinfo;
char *__progname = 0, *__progname_full = 0;

weak_alias(__progname, program_invocation_short_name);
weak_alias(__progname_full, program_invocation_name);

// Modifications start here
extern char** __environ;
static size_t __auxv;

/*
 * Initialize Musl libc in a global constructor which will be called on enclave
 * load. Ensure that the libc initialization is the first init function called
 * by giving it a priority of 0.
 *
 * Module constructor functions must be in the same file as another symbol
 * which is referenced from the main enclave bianry. This is why this function
 * does not exist in its own file. Alternatively, the linker could be explicitly
 * told to keep this symbol, by calling the linker with `-u oe_init_c`.
 */
OE_MODULE_INIT_PRIORITY(0)
void oe_init_c(void)
{
    __environ = 0;
    __auxv = 0;
    libc.auxv = &__auxv;
    libc.page_size = OE_PAGE_SIZE;
    libc.secure = 1;
}
