// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>

#include "../args.h"

OE_OCALL void CreateEnclaveHost(void* args_)
{
    printf("==== Host: CreateEnclave\n");
    CreateEnclaveArgs* args = (CreateEnclaveArgs*)args_;

    oe_result_t result = oe_create_enclave(
        args->path, args->type, args->flags, NULL, 0, NULL, 0, &args->enclave);

    args->ret = result;
}

OE_OCALL void CallEnclaveHost(void* args_)
{
    printf("==== Host: CallEnclave\n");
    CallEnclaveArgs* args = (CallEnclaveArgs*)args_;

    oe_result_t result = oe_call_enclave(args->enclave, args->func, args->args);

    args->ret = result;
}

OE_OCALL void TerminateEnclave(void* args_)
{
    printf("==== Host: TerminateEnclave\n");
    TerminateEnclaveArgs* args = (TerminateEnclaveArgs*)args_;

    oe_result_t result = oe_terminate_enclave(args->enclave);
    args->ret = result;
}

OE_OCALL void Double(void* args_)
{
    printf("==== Host: Double\n");
    if (!args_)
        return;

    int* args = (int*)args_;
    *args = *args * 2;
}

static void _test_ecall_ocall(oe_enclave_t* enclave)
{
    int num = 512;
    oe_result_t result = oe_call_enclave(enclave, "Double", &num);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave(): Double result=%u", result);

    OE_TEST(num == 1024);

    result = oe_call_enclave(enclave, "DoubleOCall", &num);
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): DoubleOCall result=%u", result);

    OE_TEST(num == 2048);
}

static void _test_create_enclave_ocall_for_host(
    const char* path,
    uint32_t flags)
{
    printf("\n_TestCreateEnclaveOCallForHost\n");

    oe_result_t result;
    oe_enclave_t* enclave;

    result = oe_create_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    CreateEnclaveArgs args = {.path = path,
                              .type = OE_ENCLAVE_TYPE_SGX,
                              .flags = flags,
                              .enclave = NULL,
                              .ret = 1};

    /* Create enclave via OCALL. */
    result = oe_call_enclave(enclave, "CreateEnclave", &args);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave(): result=%u", result);

    if (args.ret != OE_OK)
        oe_put_err("oe_call_enclave(): CreateEnclave result=%u", args.ret);

    OE_TEST(args.enclave != NULL);

    /* Test if basic ECALLs and OCALLs work for the new enclave. */
    _test_ecall_ocall(args.enclave);

    /* Test if the old enclave still works. */
    _test_ecall_ocall(enclave);

    /* Terminate the enclave. */
    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);

    result = oe_terminate_enclave(args.enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

static void _test_create_enclave_ocall_for_enclave(
    const char* path,
    uint32_t flags)
{
    printf("\n_TestCreateEnclaveOCallForEnclave\n");

    oe_result_t result;
    oe_enclave_t* enclave;

    result = oe_create_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    TestEnclaveArgs args = {.path = path, .flags = flags, .ret = 1};

    result = oe_call_enclave(enclave, "TestOCallEnclave", &args);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave(): result=%u", result);

    if (args.ret != 0)
        oe_put_err("oe_call_enclave(): TestOCallEnclave result=%u", args.ret);

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    /* Test if an enclave created via an OCALL can be used by the host. */
    _test_create_enclave_ocall_for_host(argv[1], flags);

    /* Test if an OCALL created enclave can be used by the enclave. */
    _test_create_enclave_ocall_for_enclave(argv[1], flags);

    return 0;
}
