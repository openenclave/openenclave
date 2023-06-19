// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// We force include this header on threads_pthread.c to overwrite getpid(),
// which isn't supported on Windows.
#define getpid oe_openssl_get_pid

#ifdef _MSC_VER
static __inline int oe_openssl_get_pid()
#elif __GNUC__
static __inline__ int oe_openssl_get_pid()
#endif
{
    return 0;
}
