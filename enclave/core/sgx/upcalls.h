// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

extern size_t (*oe_debug_malloc_check_upcall)(void);

extern void (
    *oe_handle_verify_report_upcall)(uint64_t arg_in, uint64_t* arg_out);

extern void (*oe_handle_get_public_key_by_policy_upcall)(uint64_t arg_in);

extern void (*oe_handle_get_public_key_upcall)(uint64_t arg_in);
