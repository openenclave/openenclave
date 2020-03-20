// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <limits.h>

#include "child_process_t.h"


void EnclaveGetMagic(void *pdata)
{
    if(pdata != 0) {
        *((unsigned int *)pdata) = 0x1234; 
    }
}


int stay_in_ocall()
{
    ocall_stay();
    return 0;
}


OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8,    /* HeapPageCount */
    8,    /* StackPageCount */
    1);   /* TCSCount */


