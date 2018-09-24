// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "string_u.c"

void test_string_edl_ecalls(oe_enclave_t* enclave)
{
    const char* str_value = "Hello, World\n";

    char str[50];
    sprintf(str, "%s", str_value);

    // char*
    OE_TEST(ecall_string_fun1(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, str_value) == 0);

    // const char*. (char* is passed in)
    OE_TEST(ecall_string_fun2(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, str_value) == 0);

    // char* in/out
    OE_TEST(ecall_string_fun3(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, "Goodbye\n") == 0);

    // Restore value.
    sprintf(str, "%s", str_value);

    // char* user check.
    OE_TEST(ecall_string_fun5(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, "Hello") == 0);

    // char* user check.
    OE_TEST(ecall_string_fun6(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, "Hello") == 0);

    // Multiple string params. One null.
    OE_TEST(ecall_string_fun7(enclave, str, NULL) == OE_OK);

    printf("=== test_string_edl_ecalls passed\n");
}

void ocall_string_fun1(char* s)
{
    ocall_string_fun1_args_t args;
    check_type<char*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    // strcmp should not crash.
    OE_TEST(strcmp(s, "Hello, World\n") == 0);
}

void ocall_string_fun2(const char* s)
{
    ocall_string_fun2_args_t args;
    // constness is discarded when marshaling.
    check_type<char*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    // strcmp should not crash.
    OE_TEST(strcmp(s, "Hello, World\n") == 0);
}

void ocall_string_fun3(char* s)
{
    ocall_string_fun3_args_t args;
    check_type<char*>(args.s);

    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    // strcmp should not crash.
    OE_TEST(strcmp(s, "Hello, World\n") == 0);

    // Write to s. Check on enclave side for new value.
    const char* new_s = "Goodbye\n";
    memcpy(s, new_s, strlen(new_s) + 1);
}

void ocall_string_fun5(char* s)
{
    ocall_string_fun5_args_t args;
    check_type<char*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ocall_string_fun5_args_t>();

    // Change value to Hello.
    s[5] = '\0';
}

void ocall_string_fun6(const char* s)
{
    ocall_string_fun6_args_t args;
    // constness is discarded when marshaling.
    check_type<char*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ocall_string_fun6_args_t>();
}

void ocall_string_fun7(char* s1, char* s2)
{
    ocall_string_fun7_args_t args;

    check_type<char*>(args.s1);
    check_type<size_t>(args.s1_len);
    check_type<char*>(args.s2);
    check_type<size_t>(args.s2_len);

    OE_TEST(s1 != NULL);
    OE_TEST(s2 == NULL);
}
