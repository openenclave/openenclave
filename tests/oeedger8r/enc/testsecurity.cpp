// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "all_t.h"

static int _secret = 11223344;

// Get address of trusted location.
int* security_get_secret_ptr()
{
    return &_secret;
}

// trusted memory address as ECALL parameter, will not leak secrets.
void security_ecall_test1(int* ptr)
{
    OE_UNUSED(ptr);
    oe_abort();
}

// trusted memory address as ECALL parameter, will not leak secrets.
void security_ecall_test2(SecurityS* s)
{
    OE_UNUSED(s);
    oe_abort();
}

// trusted memory address as ECALL parameter, will not leak secrets.
void security_ecall_test3(int* ptr)
{
    OE_UNUSED(ptr);
    oe_abort();
}

// trusted memory address as ECALL parameter, will not leak secrets.
void security_ecall_test4(SecurityS* s)
{
    OE_UNUSED(s);
    oe_abort();
}
