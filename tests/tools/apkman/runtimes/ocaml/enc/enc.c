// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "test_t.h"

void ocaml_main(char** argv);

int enc_main(int argc, char** argv)
{
    OE_UNUSED(argc);
    ocaml_main(argv);
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* Debug */
    4 * 1024, /* NumHeapPages */
    1024,     /* NumStackPages */
    2);       /* NumTCS */
