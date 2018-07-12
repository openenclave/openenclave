// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

/* Test the enclave <ctype.h> functions against the native ones. */
static void _test_ctype(oe_enclave_t* enclave)
{
    /* Test isalnum() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isalnum", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isalnum(c));
    }

    /* Test isalpha() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isalpha", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isalpha(c));
    }

    /* Test iscntrl() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_iscntrl", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)iscntrl(c));
    }

    /* Test isdigit() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isdigit", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isdigit(c));
    }

    /* Test isgraph() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isgraph", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isgraph(c));
    }

    /* Test islower() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_islower", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)islower(c));
    }

    /* Test isprint() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isprint", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isprint(c));
    }

    /* Test ispunct() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_ispunct", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)ispunct(c));
    }

    /* Test isspace() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isspace", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isspace(c));
    }

    /* Test isupper() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isupper", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isupper(c));
    }

    /* Test isxdigit() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_isxdigit", &args);
        OE_TEST(r == OE_OK);
        OE_TEST((bool)args.ret == (bool)isxdigit(c));
    }

    /* Test tolower() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_tolower", &args);
        OE_TEST(r == OE_OK);
        OE_TEST(args.ret == tolower(c));
    }

    /* Test toupper() */
    for (int c = -128; c <= 255; c++)
    {
        ctype_args_t args = {c};
        oe_result_t r = oe_call_enclave(enclave, "test_toupper", &args);
        OE_TEST(r == OE_OK);
        OE_TEST(args.ret == toupper(c));
    }
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    args_t args;

    /* Check command line argument count */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Create the enclave */
    {
        const uint32_t flags = oe_get_create_flags();
        const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

        r = oe_create_enclave(argv[1], type, flags, NULL, 0, &enclave);
        OE_TEST(r == OE_OK);
    }

    /* Invoke the test function */
    args.ret = -1;
    r = oe_call_enclave(enclave, "test_enclave", &args);
    OE_TEST(r == OE_OK);
    OE_TEST(args.ret == 0);

    /* Test <ctype.h> functions */
    _test_ctype(enclave);

    /* Terminate the enclave */
    oe_terminate_enclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
