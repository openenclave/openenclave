// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "child_thread_u.h"

#define ECALL_IN_CHILD_THREAD 0
#define DESTROY_IN_CHILD_THREAD 1
#define DESTROY_AND_ECALL_CHILD_THREAD 2
#define DESTROY_AND_OCALL_CHILD_THREAD 3

bool multi_thread_flag = true;

void stay_ocall(void)
{
    // sleep for 5 seconds.
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}

static void* child_thread_ecall(void* lpParam)
{
    multi_thread_flag = false;
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t*)lpParam;
    uint32_t magic;
    oe_result_t result = get_magic_ecall(enclave, &magic);
    OE_TEST(magic == 0x1234);
    OE_TEST(result == OE_OK);
    multi_thread_flag = true;
    return NULL;
}

static void* child_thread_destroy(void* lpParam, oe_result_t expect_result)
{
    multi_thread_flag = false;
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t*)lpParam;
    oe_result_t result = oe_terminate_enclave(enclave);
    fprintf(stdout, "oe_terminate_enclave returned: 0x%x\n", result);
    OE_TEST(result == expect_result);
    multi_thread_flag = true;
    return NULL;
}

static void* child_thread_ecall_stay(void* lpParam)
{
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t*)lpParam;
    int res;
    oe_result_t result = stay_in_ecall(enclave, &res);
    fprintf(stdout, "stay_in_ecall returned: 0x%x\n", result);
    OE_TEST(result == OE_OK);
    return NULL;
}

static void* child_thread_ocall_stay(void* lpParam)
{
    oe_enclave_t* enclave = NULL;
    enclave = (oe_enclave_t*)lpParam;
    int res;
    oe_result_t result = stay_in_ocall_ecall(enclave, &res);
    fprintf(stdout, "stay_in_ocall_ecall returned: 0x%x\n", result);
    OE_TEST(result == OE_OK);
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

    oe_result_t result = oe_create_child_thread_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    std::thread child_thread, another_child_thread;

    switch (atoi(argv[2]))
    {
        case ECALL_IN_CHILD_THREAD:
            child_thread = std::thread(child_thread_ecall, enclave);
            child_thread.join();
            OE_TEST(multi_thread_flag == true);
            break;
        case DESTROY_IN_CHILD_THREAD:
            child_thread = std::thread(child_thread_destroy, enclave, OE_OK);
            child_thread.join();
            OE_TEST(multi_thread_flag == true);
            break;
        case DESTROY_AND_ECALL_CHILD_THREAD:
            child_thread = std::thread(child_thread_ecall_stay, enclave);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            another_child_thread =
                std::thread(child_thread_destroy, enclave, OE_OK);
            child_thread.join();
            another_child_thread.join();
            OE_TEST(multi_thread_flag == true);
            break;
        case DESTROY_AND_OCALL_CHILD_THREAD:
            child_thread = std::thread(child_thread_ocall_stay, enclave);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            another_child_thread =
                std::thread(child_thread_destroy, enclave, OE_OK);
            child_thread.join();
            another_child_thread.join();
            OE_TEST(multi_thread_flag == true);
            break;
        default:
            break;
    }

    // Clean up the enclave
    if (enclave)
        oe_terminate_enclave(enclave);

    return 0;
}
