// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "switchless_one_tcs_t.h"

void enc_empty_regular(void)
{
}

void enc_empty_switchless(status_e* status)
{
    int num_waiting = 0;
    volatile status_e* _status = status;
    *_status = FUNC_WORKING;
    while (*_status != FUNC_EXIT)
    {
        num_waiting++;
    }
    oe_host_printf("enc_empty_switchless exit\n");
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* AllowDebug */
    64,       /* HeapPageCount */
    64,       /* StackPageCount */
    NUM_TCS); /* TCSCount */
