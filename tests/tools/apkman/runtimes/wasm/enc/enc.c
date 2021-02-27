// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

// For mounting host filesystem
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <sys/mount.h>

#include "test_t.h"

int main(int argc, char** argv);

int enc_main(int argc, char** argv)
{
    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

    int ret = main(argc, argv);
    oe_umount("/");

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* Debug */
    8 * 1024, /* NumHeapPages */
    1024,     /* NumStackPages */
    2);       /* NumTCS */
