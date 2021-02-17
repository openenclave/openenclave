// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define TRACE_ENCLAVE(fmt, ...) \
    printf("Enclave: %s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
