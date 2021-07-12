// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/syscall/unistd.h>

#include <stdint.h>
#include <stdio.h>

#include "test_t.h"

int main(int argc, const char** argv);

int enc_test(bool decompress, const char* in_file, const char* out_file)
{
    const char* argv[2] = {
        "zpipe",
        decompress ? "-d" : NULL,
    };

    if (in_file && out_file)
    {
        OE_TEST(oe_load_module_host_file_system() == OE_OK);
        OE_TEST(
            oe_mount("/", "/", OE_DEVICE_NAME_HOST_FILE_SYSTEM, 0, NULL) == 0);

        OE_TEST(freopen(in_file, "rb", stdin) != NULL);
        OE_TEST(freopen(out_file, "wb", stdout) != NULL);
    }

    int ret = main(decompress ? 2 : 1, argv);

    oe_umount("/");
    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages: 4 MB for snmalloc */
    16,   /* NumStackPages: 64 KB */
    2);   /* NumTCS */

/* OP-TEE requires __stack_chk_guard to be defined. */
void* __stack_chk_guard = (void*)0x0000aaff;

#define TA_UUID                                            \
    { /* 71b0822f-42a3-4543-a97c-ca491f76b82c */           \
        0x71b0822f, 0x42a3, 0x4543,                        \
        {                                                  \
            0xa9, 0x7c, 0xca, 0x49, 0x1f, 0x76, 0xb8, 0x2c \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    /* 1 MB heap */
    1 * 1024 * 1024,
    /* zlib requires at least 16 KB stack */
    16 * 1024,
    0,
    "1.0.0",
    "zlib test")
