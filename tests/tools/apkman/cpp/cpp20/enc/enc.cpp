// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <cstdio>
#include "test_t.h"

int main(int argc, char** argv);

int enc_main(int argc, char** argv)
{
    return main(argc, argv);
}

const void* __dso_handle = NULL;

extern "C" int get_nprocs()
{
    return 4;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    8);   /* NumTCS */
