// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
  Since most of the libcxxrt tests are tested based on the
  comparison between log file generated by the enclave with
  log generated by system, one can't add any debug prints
  to this file. If added, the tests will fail because of
  additional prints in enclave log, which won't be there in
  system generated log. For more details please refer
  README.md file
*/

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/tests.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include "libcxxrt_t.h"

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    ocall_exit(status);
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

Handler signal(int signal, Handler)
{
    /* Ignore! */
    return NULL;
}

extern "C" int close(int fd)
{
    OE_TEST("close() panic" == NULL);
    return 0;
}

extern "C" int test(char** name)
{
    extern const char* __TEST__NAME;
    static const char* argv[] = {
        "test",
        NULL,
    };
    static int argc = sizeof(argv) / sizeof(argv[0]);
    *name = oe_host_strndup(__TEST__NAME, OE_SIZE_MAX);
    return main(argc, argv);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
