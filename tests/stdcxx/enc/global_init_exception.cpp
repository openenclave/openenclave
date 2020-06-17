// Copyright (c) Open Enclave SDK contributors.
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
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
