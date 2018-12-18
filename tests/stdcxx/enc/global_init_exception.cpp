// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdexcept>

/* This test is to check that oe_create_enclave does not return success
   when enclave initialisation fails */

class Foo
{
  public:
    Foo()
    {
        throw std::runtime_error("Aborting..");
    }
};

Foo f;

OE_ECALL void foo()
{
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
