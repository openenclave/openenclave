// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

OE_ECALL void Double(void* args_)
{
    oe_host_printf("==== Enclave: Double\n");

    if (!args_ || !oe_is_outside_enclave(args_, sizeof(int)))
        return;

    int* args = (int*)args_;
    *args = *args * 2;
}

OE_ECALL void DoubleOCall(void* args_)
{
    oe_host_printf("==== Enclave: DoubleOCall\n");

    if (!args_ || !oe_is_outside_enclave(args_, sizeof(int)))
        return;

    OE_TEST(oe_call_host("Double", args_) == OE_OK);
}

OE_ECALL void CreateEnclave(void* args_)
{
    oe_host_printf("==== Enclave: CreateEnclave\n");
    CreateEnclaveArgs* args = (CreateEnclaveArgs*)args_;

    if (!args || !oe_is_outside_enclave(args, sizeof(*args)))
    {
        oe_abort();
        return;
    }

    /* Create enclave with an OCALL from host. */
    args->ret = oe_call_host("CreateEnclaveHost", args);
}

static oe_enclave_t* _create_enclave(TestEnclaveArgs* args)
{
    /* Allocate memory for the CreateEnclaveArgs struct. */
    CreateEnclaveArgs* create_args =
        (CreateEnclaveArgs*)oe_host_malloc(sizeof(CreateEnclaveArgs));

    OE_TEST(create_args != NULL);

    /* Populate fields. */
    create_args->path = args->path;
    create_args->type = OE_ENCLAVE_TYPE_SGX;
    create_args->flags = args->flags;
    create_args->enclave = NULL;
    create_args->ret = 1;

    /* Create enclave with an OCALL from host. */
    oe_result_t result = oe_call_host("CreateEnclaveHost", create_args);
    OE_TEST(result == OE_OK);
    OE_TEST(create_args->ret == OE_OK);

    /* Return enclave. */
    oe_enclave_t* enclave = create_args->enclave;
    oe_host_free(create_args);
    OE_TEST(enclave != NULL);
    return enclave;
}

static void _call_enclave(oe_enclave_t* enclave, const char* func)
{
    /* Allocate memory for calling the enclave. */
    CallEnclaveArgs* call_args =
        (CallEnclaveArgs*)oe_host_malloc(sizeof(CallEnclaveArgs));

    OE_TEST(call_args != NULL);

    /* Fill struct values. */
    call_args->enclave = enclave;

    call_args->func = oe_host_strndup(func, OE_SIZE_MAX);
    OE_TEST(call_args->func != NULL);

    call_args->args = oe_host_malloc(sizeof(int));
    OE_TEST(call_args->args != NULL);
    *((int*)call_args->args) = 123;

    call_args->ret = 1;

    /* Test calling the enclave via an OCALL. */
    oe_result_t result = oe_call_host("CallEnclaveHost", call_args);
    OE_TEST(result == OE_OK);
    OE_TEST(call_args->ret == OE_OK);
    OE_TEST(*((int*)call_args->args) == 246);

    oe_host_free(call_args->args);
    oe_host_free(call_args->func);
    oe_host_free(call_args);
}

static void _terminate_enclave(oe_enclave_t* enclave)
{
    /* Allocate memory for terminating the enclave. */
    TerminateEnclaveArgs* terminate_args =
        (TerminateEnclaveArgs*)oe_host_malloc(sizeof(TerminateEnclaveArgs));

    OE_TEST(terminate_args != NULL);

    /* Fill struct values. */
    terminate_args->enclave = enclave;
    terminate_args->ret = 1;

    /* Call terminate enclave via OCALL. */
    oe_result_t result = oe_call_host("TerminateEnclave", terminate_args);
    OE_TEST(result == OE_OK);
    OE_TEST(terminate_args->ret == OE_OK);

    oe_host_free(terminate_args);
}

OE_ECALL void TestOCallEnclave(void* args_)
{
    oe_host_printf("==== Host: TestOCallEnclave\n");

    TestEnclaveArgs* args = (TestEnclaveArgs*)args_;

    if (!args || !oe_is_outside_enclave(args, sizeof(*args)))
    {
        oe_abort();
        return;
    }

    /* Create Enclave via OCALL. */
    oe_enclave_t* enclave = _create_enclave(args);
    OE_TEST(enclave != NULL);

    /* Test ECALL on this enclave. */
    _call_enclave(enclave, "Double");

    /* Test OCALL on this enclave. */
    _call_enclave(enclave, "DoubleOCall");

    /* Test terminating the enclave. */
    _terminate_enclave(enclave);

    args->ret = 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    256,  /* HeapPageCount */
    128,  /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
