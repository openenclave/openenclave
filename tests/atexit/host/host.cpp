// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <unistd.h>

#include "atexit_u.h"

oe_enclave_t* enclave = NULL;
int global_var = 0;

void ocall_atexit1(void)
{
    global_var++;
}

void ocall_atexit2(void)
{
        global_var+=3;
        unsigned int magic = 2;
        oe_result_t result = EnclaveGetMagic(enclave, &magic);
        //should fail since enclave was destoryed
        OE_TEST(result == OE_REENTRANT_ECALL);
        OE_TEST(2 == magic);
        global_var += 2;
        return;
}

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TEST_NUMBER\n", argv[0]);
        exit(1);
    }

    int expected_value = -1; 
    const uint32_t flags = oe_get_create_flags();

    oe_result_t result =
        oe_create_atexit_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

   switch (atoi(argv[2]))
    {
        case 0:
            expected_value = 1;
            result = enclave_atexit_func1(enclave);
            break;
        case 1:
            expected_value = 32;
            result = enclave_atexit_func2(enclave);
            break;
        case 2:
            expected_value = 5;
            result = enclave_atexit_func3(enclave);
            break;
        default:
            break;
    }
    OE_TEST(result == OE_OK);            
    // Clean up the enclave
    if (enclave)
        oe_terminate_enclave(enclave);
 

    OE_TEST(global_var == expected_value);

    return 0;
}
