// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define TRACE_ENCLAVE(fmt, ...) \
    printf("Enclave: %s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
