// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// The line numbers in this file are referenced by the gdb
// test script commands.gdb. If you edit this file, update the
// test script as well.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "non_debug_t.h"
#include "openenclave/bits/defs.h"

OE_NEVER_INLINE
void enc_foo(void)
{
}

void enc_fcn(void)
{
    enc_foo();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug: Enclave will however be created without
             OE_ENCLAVE_FLAG_DEBUG */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
