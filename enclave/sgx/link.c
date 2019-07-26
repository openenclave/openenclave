// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include "../core/sgx/upcalls.h"
#include "internal_t.h"
#include "report.h"

//
// The _start function (see start.S) calls this function to install upcalls.
// Upcalls are callbacks invoked by liboecore to invoke functions in
// liboeenclave. This backward dependency is required because the upcalls
// depend on liboelibc and liboembedtls, which are unavailable to liboecore.
//
void oe_link_enclave(void)
{
    oe_set_verify_report_upcall(oe_handle_verify_report_upcall);

    oe_set_get_public_key_by_policy_upcall(
        oe_handle_get_public_key_by_policy_upcall);

    oe_set_get_public_key_upcall(oe_handle_get_public_key_upcall);
}
