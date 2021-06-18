// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include "debug_mode_t.h"

int is_enclave_debug_allowed();

int test(void)
{
    return is_enclave_debug_allowed();
}
