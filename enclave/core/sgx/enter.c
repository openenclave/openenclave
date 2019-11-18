// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/types.h>

#include "td.h"

/**
 * This function must be named call_function because currently WinDbg looks
 * for such a named function to transition out of the enclave for ecall
 * stack-stitching.
 */
void call_function(
    uint64_t arg1,          /* rdi */
    uint64_t arg2,          /* rsi */
    uint64_t cssa,          /* rdx */
    uint64_t host_ret_addr, /* rcx */
    uint64_t host_rsp,      /* r8 */
    uint64_t host_rbp,      /* r9 */
    void* tcs)              /* on stack */
{
    td_t* td = td_from_tcs(tcs);
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    uint16_t func = oe_get_func_from_call_arg1(arg1);
    uint8_t handling_exception =
        (cssa != 0) ||
        (code == OE_CODE_ECALL && func == OE_ECALL_VIRTUAL_EXCEPTION_HANDLER);

    if (!handling_exception)
    {
        // In case of an ecall or ocall return, update the host return location
        // information so that the ocalls can be made to the correct location.
        td->host_rsp = host_rsp;
        td->host_rbp = host_rbp;
        td->host_rcx = host_ret_addr;
    }

    __oe_handle_main(arg1, arg2, cssa, tcs, &arg1, &arg2);
    oe_exit_enclave(arg1, arg2, host_ret_addr, host_rsp, host_rbp);
}
