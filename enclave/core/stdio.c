// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>

OE_FILE* const oe_stdin = ((OE_FILE*)0x1000000000000001);
OE_FILE* const oe_stdout = ((OE_FILE*)0x1000000000000002);
OE_FILE* const oe_stderr = ((OE_FILE*)0x1000000000000003);
