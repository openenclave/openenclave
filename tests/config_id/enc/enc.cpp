// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include "config_id_t.h"

int enclave_test_config_id()
{
    fprintf(stdout, "enclave_config_id_test_kss_properties invoked\n");
    /*
     * Current test cases are written for non ice-lake platform.
     * Additional code need to be added here to verify the
     * config id/ svn properties on ice lake platforms
     */
    return OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    64,   /* NumStackPages */
    1);   /* NumTCS */
