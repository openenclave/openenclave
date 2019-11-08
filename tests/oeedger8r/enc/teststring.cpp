// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "all_t.h"

void test_string_edl_ocalls()
{
    const char* str_value = "Hello, World\n";

    char str[50];
    sprintf(str, "%s", str_value);

    // char*
    OE_TEST(ocall_string_fun1(str) == OE_OK);
    OE_TEST(strcmp(str, str_value) == 0);

    // const char*. (char* is passed in)
    OE_TEST(ocall_string_fun2(str) == OE_OK);
    OE_TEST(strcmp(str, str_value) == 0);

    // char* in/out
    OE_TEST(ocall_string_fun3(str) == OE_OK);
    OE_TEST(strcmp(str, "Goodbye\n") == 0);

    // Restore value.
    sprintf(str, "%s", str_value);

    // char* user check.
    OE_TEST(ocall_string_fun5(str) == OE_OK);

    // char* user check.
    OE_TEST(ocall_string_fun6(str) == OE_OK);

    // Multiple string params. One null.
    OE_TEST(ocall_string_fun7(str, NULL) == OE_OK);

    // Test scenario where host does not null-terminate an
    // in-out string. The first call preserves the null-terminator.
    // The second call does not preserve the null terminator.
    {
        char str1[] = "Hello";
        OE_TEST(ocall_string_no_null_terminator(false, str1) == OE_OK);
        OE_TEST(
            ocall_string_no_null_terminator(true, str1) ==
            OE_INVALID_PARAMETER);
    }

    printf("=== test_string_edl_ocalls passed\n");
}

void ecall_string_fun1(char* s)
{
    ecall_string_fun1_args_t args;
    check_type<char*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    size_t s_len = strlen(s) + 1;
    OE_TEST(oe_is_within_enclave(s, s_len));

    OE_TEST(strcmp(s, "Hello, World\n") == 0);
}

void ecall_string_fun2(const char* s)
{
    ecall_string_fun2_args_t args;
    // constness is discarded when marshaling.
    check_type<char*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    size_t s_len = strlen(s) + 1;
    OE_TEST(oe_is_within_enclave(s, s_len));

    OE_TEST(strcmp(s, "Hello, World\n") == 0);
}

void ecall_string_fun3(char* s)
{
    ecall_string_fun3_args_t args;
    check_type<char*>(args.s);

    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    size_t s_len = strlen(s) + 1;
    OE_TEST(oe_is_within_enclave(s, s_len));

    OE_TEST(strcmp(s, "Hello, World\n") == 0);

    // Write to s. Check on host side for new value.
    const char* new_s = "Goodbye\n";
    memcpy(s, new_s, strlen(new_s) + 1);
}

void ecall_string_fun5(char* s)
{
    ecall_string_fun5_args_t args;
    check_type<char*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ecall_string_fun5_args_t>();

    // Check that s has not been copied over.
    size_t s_len = strlen(s) + 1;
    OE_TEST(oe_is_outside_enclave(s, s_len));

    // Change value to Hello.
    s[5] = '\0';
}

void ecall_string_fun6(const char* s)
{
    ecall_string_fun6_args_t args;
    // constness is discarded when marshaling.
    check_type<char*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ecall_string_fun6_args_t>();

    // Check that s has not been copied over.
    size_t s_len = strlen(s) + 1;
    OE_TEST(oe_is_outside_enclave(s, s_len));
}

void ecall_string_fun7(char* s1, char* s2)
{
    ecall_string_fun7_args_t args;

    check_type<char*>(args.s1);
    check_type<size_t>(args.s1_len);
    check_type<char*>(args.s2);
    check_type<size_t>(args.s2_len);

    OE_TEST(s1 != NULL);
    OE_TEST(s2 == NULL);
}

void ecall_string_no_null_terminator(char* s1, char* s2)
{
    OE_UNUSED(s1);
    OE_UNUSED(s2);
}

void ecall_wstring_no_null_terminator(wchar_t* s1, wchar_t* s2)
{
    OE_UNUSED(s1);
    OE_UNUSED(s2);
}

void test_wstring_edl_ocalls()
{
    const wchar_t* str_value = L"Hello, World\n";
    wchar_t str[50];

    if (!g_enabled[TYPE_WCHAR_T])
        return;

    swprintf(str, 50, L"%S", str_value);

    // char*
    OE_TEST(ocall_wstring_fun1(str) == OE_OK);
    OE_TEST(wcscmp(str, str_value) == 0);

    // const char*. (char* is passed in)
    OE_TEST(ocall_wstring_fun2(str) == OE_OK);
    OE_TEST(wcscmp(str, str_value) == 0);

    // char* in/out
    OE_TEST(ocall_wstring_fun3(str) == OE_OK);
    OE_TEST(wcscmp(str, L"Goodbye\n") == 0);

    // Restore value.
    swprintf(str, 50, L"%S", str_value);

    // char* user check.
    OE_TEST(ocall_wstring_fun5(str) == OE_OK);

    // char* user check.
    OE_TEST(ocall_wstring_fun6(str) == OE_OK);

    // Multiple string params. One null.
    OE_TEST(ocall_wstring_fun7(str, NULL) == OE_OK);

    // Test scenario where host does not null-terminate an
    // in-out string. The first call preserves the null-terminator.
    // The second call does not preserve the null terminator.
    {
        wchar_t str1[] = L"Hello";
        OE_TEST(ocall_wstring_no_null_terminator(false, str1) == OE_OK);
        OE_TEST(
            ocall_wstring_no_null_terminator(true, str1) ==
            OE_INVALID_PARAMETER);
    }

    printf("=== test_wstring_edl_ocalls passed\n");
}

void ecall_wstring_fun1(wchar_t* s)
{
    ecall_wstring_fun1_args_t args;
    check_type<wchar_t*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    size_t s_len = wcslen(s) + 1;
    OE_TEST(oe_is_within_enclave(s, s_len * sizeof(wchar_t)));

    OE_TEST(wcscmp(s, L"Hello, World\n") == 0);
}

void ecall_wstring_fun2(const wchar_t* s)
{
    ecall_wstring_fun2_args_t args;
    // constness is discarded when marshaling.
    check_type<wchar_t*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    size_t s_len = wcslen(s) + 1;
    OE_TEST(oe_is_within_enclave(s, s_len * sizeof(wchar_t)));

    OE_TEST(wcscmp(s, L"Hello, World\n") == 0);
}

void ecall_wstring_fun3(wchar_t* s)
{
    ecall_wstring_fun3_args_t args;
    check_type<wchar_t*>(args.s);

    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    size_t s_len = wcslen(s) + 1;
    OE_TEST(oe_is_within_enclave(s, s_len * sizeof(wchar_t)));

    OE_TEST(wcscmp(s, L"Hello, World\n") == 0);

    // Write to s. Check on host side for new value.
    const wchar_t* new_s = L"Goodbye\n";
    memcpy(s, new_s, (wcslen(new_s) + 1) * sizeof(wchar_t));
}

void ecall_wstring_fun5(wchar_t* s)
{
    ecall_wstring_fun5_args_t args;
    check_type<wchar_t*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ecall_wstring_fun5_args_t>();

    // Check that s has not been copied over.
    size_t s_len = wcslen(s) + 1;
    OE_TEST(oe_is_outside_enclave(s, s_len * sizeof(wchar_t)));

    // Change value to Hello.
    s[5] = L'\0';
}

void ecall_wstring_fun6(const wchar_t* s)
{
    ecall_wstring_fun6_args_t args;
    // constness is discarded when marshaling.
    check_type<wchar_t*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ecall_wstring_fun6_args_t>();

    // Check that s has not been copied over.
    size_t s_len = wcslen(s) + 1;
    OE_TEST(oe_is_outside_enclave(s, s_len * sizeof(wchar_t)));
}

void ecall_wstring_fun7(wchar_t* s1, wchar_t* s2)
{
    ecall_wstring_fun7_args_t args;

    check_type<wchar_t*>(args.s1);
    check_type<size_t>(args.s1_len);
    check_type<wchar_t*>(args.s2);
    check_type<size_t>(args.s2_len);

    OE_TEST(s1 != NULL);
    OE_TEST(s2 == NULL);
}
