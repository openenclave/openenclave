// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <compiler.h>
#include <tee_ta_api.h>
#include <utee_syscalls.h>

struct utee_params;

TEE_Result __utee_entry(
    unsigned long func,
    unsigned long session_id,
    struct utee_params* up,
    unsigned long cmd_id);

void __ta_entry(
    unsigned long func,
    unsigned long session_id,
    struct utee_params* up,
    unsigned long cmd_id) __noreturn;

void __ta_entry(
    unsigned long func,
    unsigned long session_id,
    struct utee_params* up,
    unsigned long cmd_id)
{
    TEE_Result res = TEE_SUCCESS;

    res = __utee_entry(func, session_id, up, cmd_id);
    utee_return(res);
}
