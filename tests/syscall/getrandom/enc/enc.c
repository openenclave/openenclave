// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <sys/random.h>

#include "getrandom_t.h"

void test_getrandom()
{
    /* Test getrandom SYSCALL via the libc API */
    char buf[256];
    size_t buflen = 256;
    ssize_t size;

    /* Test with the zero flags (required by OE) */
    size = getrandom((void*)buf, sizeof(buflen), 0);
    OE_TEST((size_t)size == sizeof(buflen));

    /* Test with unsupported flags */
    OE_TEST(getrandom((void*)buf, sizeof(buflen), GRND_RANDOM) == -1);
    OE_TEST(errno == EINVAL);
    OE_TEST(getrandom((void*)buf, sizeof(buflen), GRND_NONBLOCK) == -1);
    OE_TEST(errno == EINVAL);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    512,  /* NumStackPages */
    1);   /* NumTCS */
