// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

// For mounting host filesystem
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <sys/mount.h>

#include "test_t.h"

int main(int argc, char** argv);

int enc_main(int argc, char** argv)
{
    return main(argc, argv);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
