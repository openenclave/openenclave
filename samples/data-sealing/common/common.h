// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

extern const char* enclave_name;

#define TRACE_ENCLAVE(fmt, ...)    \
                                   \
    printf(                        \
        "%s ***%s(%d): " fmt "\n", \
        enclave_name,              \
        __FILE__,                  \
        __LINE__,                  \
        ##__VA_ARGS__)
