// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// We force include this header on threads_pthread.c to overwrite getpid(),
// which isn't supported on Windows.
#define getpid oe_openssl_get_pid

int oe_openssl_get_pid()
{
    return 0;
}
