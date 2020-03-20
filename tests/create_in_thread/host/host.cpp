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

#include "create_in_thread_u.h"

bool MULTI_THREAD_FLAG = true;

void ocall_stay(void)
{
    //sleep for 5 seconds.
    sleep(5);
}

static void *child_thread_ecall(void * lpParam)
{
    MULTI_THREAD_FLAG = false;
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t *)lpParam;
    unsigned int magic;
    oe_result_t result = EnclaveGetMagic(enclave,&magic);
    OE_TEST(0x1234 == magic);
    OE_TEST(result == OE_OK);
    MULTI_THREAD_FLAG = true;
    return NULL;
}

static void *child_thread_destory(void * lpParam)
{
    MULTI_THREAD_FLAG = false;
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t *)lpParam;
    oe_result_t result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);
    MULTI_THREAD_FLAG = true;
    return NULL;
}

static void *child_thread_stay(void * lpParam)
{
    MULTI_THREAD_FLAG = false;
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t *)lpParam;
    int res;
    oe_result_t result = stay_in_ocall(enclave, &res);
    OE_TEST(result == OE_OUT_OF_THREADS);
    MULTI_THREAD_FLAG = true;
    return NULL;
}

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TEST_NUMBER\n", argv[0]);
        exit(1);
    }
    oe_enclave_t* enclave;
    const uint32_t flags = oe_get_create_flags();

    oe_result_t result =
        oe_create_create_in_thread_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    pthread_t thread_id;

    switch (atoi(argv[2]))
    {
        case 0:
             OE_TEST(0 == pthread_create(&thread_id,NULL,child_thread_ecall, enclave));
             OE_TEST(0 == pthread_join(thread_id,NULL));
             OE_TEST(true == MULTI_THREAD_FLAG );
             break;
         case 1:
             OE_TEST(0 == pthread_create(&thread_id,NULL,child_thread_destory, enclave));
             OE_TEST(0 == pthread_join(thread_id,NULL));
             OE_TEST(true == MULTI_THREAD_FLAG);
             break;
         case 2:
             pthread_t thread_id_sec;
             OE_TEST(0 == pthread_create(&thread_id,NULL,child_thread_stay, enclave));        
             OE_TEST(0 == pthread_create(&thread_id_sec,NULL,child_thread_destory, enclave));
             OE_TEST(0 == pthread_join(thread_id,NULL));
             OE_TEST(0 == pthread_join(thread_id_sec,NULL));
             OE_TEST(true == MULTI_THREAD_FLAG);

              break;
            default:
              break;
    }

    // Clean up the enclave
    if (enclave)
        oe_terminate_enclave(enclave);

    return 0;
}
