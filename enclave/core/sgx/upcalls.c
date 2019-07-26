// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "upcalls.h"

oe_verify_report_upcall_t oe_verify_report_upcall;

oe_get_public_key_by_policy_upcall_t oe_get_public_key_by_policy_upcall;

oe_get_public_key_upcall_t oe_get_public_key_upcall;

void oe_set_verify_report_upcall(oe_verify_report_upcall_t upcall)
{
    oe_verify_report_upcall = upcall;
}

void oe_set_get_public_key_by_policy_upcall(
    oe_get_public_key_by_policy_upcall_t upcall)
{
    oe_get_public_key_by_policy_upcall = upcall;
}

void oe_set_get_public_key_upcall(oe_get_public_key_upcall_t upcall)
{
    oe_get_public_key_upcall = upcall;
}
