// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdbool.h>
#include <openenclave/internal/sgx/td.h>

void oe_initialize_is_enclave_debug_allowed(oe_sgx_td_t* td);
bool oe_is_enclave_debug_allowed();
