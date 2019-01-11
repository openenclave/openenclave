// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdexcept>
#include "stdcxx_t.h"

/* This test is to check that oe_create_stdcxx_enclave does not return success
   when enclave initialisation fails */

class foo
{
  public:
    foo()
    {
        throw std::runtime_error("Aborting..");
    }
};

foo f;

int enc_test(bool*, bool*, size_t*)
{
    return -1;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
