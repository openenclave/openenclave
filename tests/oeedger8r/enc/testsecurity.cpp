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
    // Since host does serialization completely, the contents of ptr
    // will not match _secret.
    OE_TEST(*ptr != _secret);

    // ptr must lie within the enclave.
    OE_TEST(oe_is_within_enclave(ptr, sizeof(*ptr)));

    printf("_secret = %d, *ptr = %d\n", _secret, ptr);

    printf("_secret not leaked.\n");
}
