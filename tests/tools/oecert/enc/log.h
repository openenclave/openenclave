// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

#include <stdio.h>

#define TRACE_ENCLAVE(fmt, ...) \
                                \
    printf("Enclave: ***%s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
