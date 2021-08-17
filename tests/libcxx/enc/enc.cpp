// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <thread>
#include <vector>
#include "libcxx_t.h"

extern const char* __test__;

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    host_exit(status);
    abort();
}

extern "C" void _Exit(int status)
{
    _exit(status);
    abort();
}

extern "C" void exit(int status)
{
    _exit(status);
    abort();
}

typedef void (*Handler)(int signal);

Handler signal(int, Handler)
{
    /* Ignore! */
    return NULL;
}

extern "C" int close(int fd)
{
    OE_UNUSED(fd);
    OE_TEST("close() panic" == NULL);
    return 0;
}

int enc_test(char test_name[STRLEN])
{
    static const char* argv[] = {
        "test",
        NULL,
    };
    static const int argc = sizeof(argv) / sizeof(argv[0]);

    extern const char* __TEST__NAME;

    strncpy(test_name, __TEST__NAME, STRLEN);
    test_name[STRLEN - 1] = '\0';

    printf("RUNNING: %s\n", __TEST__NAME);
    return main(argc, argv);
}

OE_SET_ENCLAVE_SGX(
    1,                   /* ProductID */
    1,                   /* SecurityVersion */
    true,                /* Debug */
#ifdef FULL_LIBCXX_TESTS /* Full tests require large heap memory. */
    12288,               /* NumHeapPages */
#else
    512, /* NumHeapPages */
#endif
    512, /* NumStackPages */
    8);  /* NumTCS */
