// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>
#include <stdio.h>

ELIBC_FILE* const elibc_stdin = ((ELIBC_FILE*)0x1000000000000001);
ELIBC_FILE* const elibc_stdout = ((ELIBC_FILE*)0x1000000000000002);
ELIBC_FILE* const elibc_stderr = ((ELIBC_FILE*)0x1000000000000003);
