// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CORE_SGX_TRACEE_H
#define _OE_CORE_SGX_TRACEE_H

#include <openenclave/bits/result.h>
#include <openenclave/corelibc/stdbool.h>
#include <openenclave/internal/sgx/td.h>

oe_result_t oe_sgx_initialize_simulation_mode_cache(oe_sgx_td_t* td);

bool oe_sgx_is_in_simulation_mode();

#endif /* _OE_CORE_SGX_TRACEE_H */
