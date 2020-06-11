// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

/* This function exists solely to create a difference in the MRENCLAVE
 * value from the basic oesign_test_enc enclave, and needs to be passed
 * to the linker as an --undefined symbol */
void oesign_test_extra_function()
{
}

/* NOTE: These need to be kept in sync with the default values set by
 * test-inputs/make-oesign-config.py */
OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    1,    /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
