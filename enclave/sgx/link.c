// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include "../asym_keys.h"
#include "../core/sgx/upcalls.h"
#include "report.h"

// start.S (the compilation unit containing the entry point) calls this
// function to dynamically install upcalls into liboecore.
void oe_link_enclave(void)
{
    oe_handle_verify_report_upcall = oe_handle_verify_report;

    oe_handle_get_public_key_by_policy_upcall =
        oe_handle_get_public_key_by_policy;

    oe_handle_get_public_key_upcall = oe_handle_get_public_key;

#if defined(OE_USE_DEBUG_MALLOC)
    oe_debug_malloc_check_upcall = oe_debug_malloc_check;
#endif /* defined(OE_USE_DEBUG_MALLOC) */
}
