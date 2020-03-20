// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <limits.h>

#include "atexit_t.h"

void EnclaveGetMagic(void *pdata)
{
    if(pdata != 0) {
         *((unsigned int *)pdata) = 0x1234;
    }
}

//this function would be called by atexit
void funcExit1(void)
{
        //++global_var1;
        ocall_atexit1();
}

void enclave_atexit_func1(void)
{
        atexit(funcExit1);
}

//atexit should at least support 32 call back functions
void enclave_atexit_func2(void)
{
        atexit(funcExit1);     
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);     
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);     
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);     //16
        atexit(funcExit1);     
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);     
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);     
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);
        atexit(funcExit1);     //32
}

//ocall->ecall
void funcExit2(void)
{
        ocall_atexit2();
}


void enclave_atexit_func3(void)
{
        atexit(funcExit2);
}



OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8,    /* HeapPageCount */
    8,    /* StackPageCount */
    1);   /* TCSCount */


