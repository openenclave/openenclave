// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <wchar.h>
#include "all_u.h"

#define STR_LENGTH 50

oe_result_t ecall_string_no_null_terminator_modified(
    oe_enclave_t* enclave,
    char* s1,
    char* s2,
    size_t s1_len,
    size_t s2_len)
{
    oe_result_t _result = OE_FAILURE;

    static uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;

    /* Marshalling struct */
    ecall_string_no_null_terminator_args_t _args, *_pargs_in = NULL,
                                                  *_pargs_out = NULL;

    /* Marshalling buffer and sizes */
    size_t _input_buffer_size = 0;
    size_t _output_buffer_size = 0;
    size_t _total_buffer_size = 0;
    uint8_t* _buffer = NULL;
    uint8_t* _input_buffer = NULL;
    uint8_t* _output_buffer = NULL;
    size_t _input_buffer_offset = 0;
    size_t _output_buffer_offset = 0;
    size_t _output_bytes_written = 0;

    /* Fill marshalling struct */
    memset(&_args, 0, sizeof(_args));
    _args.s1 = (char*)s1;
    _args.s1_len = (s1) ? s1_len : 0;
    _args.s2 = (char*)s2;
    _args.s2_len = (s2) ? s2_len : 0;

    /* Compute input buffer size. Include in and in-out parameters. */
    OE_ADD_SIZE(
        _input_buffer_size, sizeof(ecall_string_no_null_terminator_args_t));
    if (s1)
        OE_ADD_SIZE(_input_buffer_size, _args.s1_len * sizeof(char));
    if (s2)
        OE_ADD_SIZE(_input_buffer_size, _args.s2_len * sizeof(char));

    /* Compute output buffer size. Include out and in-out parameters. */
    OE_ADD_SIZE(
        _output_buffer_size, sizeof(ecall_string_no_null_terminator_args_t));
    if (s2)
        OE_ADD_SIZE(_output_buffer_size, _args.s2_len * sizeof(char));

    /* Allocate marshalling buffer */
    _total_buffer_size = _input_buffer_size;
    OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);

    _buffer = (uint8_t*)malloc(_total_buffer_size);
    _input_buffer = _buffer;
    _output_buffer = _buffer + _input_buffer_size;
    if (_buffer == NULL)
    {
        _result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Serialize buffer inputs (in and in-out parameters) */
    _pargs_in = (ecall_string_no_null_terminator_args_t*)_input_buffer;
    OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));

    OE_WRITE_IN_PARAM(s1, _args.s1_len * sizeof(char), char*);
    OE_WRITE_IN_OUT_PARAM(s2, _args.s2_len * sizeof(char), char*);

    /* Copy args structure (now filled) to input buffer */
    memcpy(_pargs_in, &_args, sizeof(*_pargs_in));

    /* Call enclave function */
    if ((_result = oe_call_enclave_function(
             enclave,
             &global_id,
             __all_ecall_info_table[all_fcn_id_ecall_string_no_null_terminator]
                 .name,
             _input_buffer,
             _input_buffer_size,
             _output_buffer,
             _output_buffer_size,
             &_output_bytes_written)) != OE_OK)
        goto done;

    /* Set up output arg struct pointer */
    _pargs_out = (ecall_string_no_null_terminator_args_t*)_output_buffer;
    OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));

    /* Check if the call succeeded */
    if ((_result = _pargs_out->_result) != OE_OK)
        goto done;

    /* Currently exactly _output_buffer_size bytes must be written */
    if (_output_bytes_written != _output_buffer_size)
    {
        _result = OE_FAILURE;
        goto done;
    }

    /* Unmarshal return value and out, in-out parameters */
    OE_CHECK_NULL_TERMINATOR(
        _output_buffer + _output_buffer_offset, _args.s2_len);
    OE_READ_IN_OUT_PARAM(s2, (size_t)(_args.s2_len * sizeof(char)));

    _result = OE_OK;
done:
    if (_buffer)
        free(_buffer);
    return _result;
}

oe_result_t ecall_wstring_no_null_terminator_modified(
    oe_enclave_t* enclave,
    wchar_t* s1,
    wchar_t* s2,
    size_t s1_len,
    size_t s2_len)
{
    oe_result_t _result = OE_FAILURE;

    static uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;

    /* Marshalling struct */
    ecall_wstring_no_null_terminator_args_t _args, *_pargs_in = NULL,
                                                   *_pargs_out = NULL;

    /* Marshalling buffer and sizes */
    size_t _input_buffer_size = 0;
    size_t _output_buffer_size = 0;
    size_t _total_buffer_size = 0;
    uint8_t* _buffer = NULL;
    uint8_t* _input_buffer = NULL;
    uint8_t* _output_buffer = NULL;
    size_t _input_buffer_offset = 0;
    size_t _output_buffer_offset = 0;
    size_t _output_bytes_written = 0;

    /* Fill marshalling struct */
    memset(&_args, 0, sizeof(_args));
    _args.s1 = (wchar_t*)s1;
    _args.s1_len = (s1) ? s1_len : 0;
    _args.s2 = (wchar_t*)s2;
    _args.s2_len = (s2) ? s2_len : 0;

    /* Compute input buffer size. Include in and in-out parameters. */
    OE_ADD_SIZE(
        _input_buffer_size, sizeof(ecall_wstring_no_null_terminator_args_t));
    if (s1)
        OE_ADD_SIZE(_input_buffer_size, _args.s1_len * sizeof(wchar_t));
    if (s2)
        OE_ADD_SIZE(_input_buffer_size, _args.s2_len * sizeof(wchar_t));

    /* Compute output buffer size. Include out and in-out parameters. */
    OE_ADD_SIZE(
        _output_buffer_size, sizeof(ecall_wstring_no_null_terminator_args_t));
    if (s2)
        OE_ADD_SIZE(_output_buffer_size, _args.s2_len * sizeof(wchar_t));

    /* Allocate marshalling buffer */
    _total_buffer_size = _input_buffer_size;
    OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);

    _buffer = (uint8_t*)malloc(_total_buffer_size);
    _input_buffer = _buffer;
    _output_buffer = _buffer + _input_buffer_size;
    if (_buffer == NULL)
    {
        _result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Serialize buffer inputs (in and in-out parameters) */
    _pargs_in = (ecall_wstring_no_null_terminator_args_t*)_input_buffer;
    OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));

    OE_WRITE_IN_PARAM(s1, _args.s1_len * sizeof(wchar_t), wchar_t*);
    OE_WRITE_IN_OUT_PARAM(s2, _args.s2_len * sizeof(wchar_t), wchar_t*);

    /* Copy args structure (now filled) to input buffer */
    memcpy(_pargs_in, &_args, sizeof(*_pargs_in));

    /* Call enclave function */
    if ((_result = oe_call_enclave_function(
             enclave,
             &global_id,
             __all_ecall_info_table[all_fcn_id_ecall_wstring_no_null_terminator]
                 .name,
             _input_buffer,
             _input_buffer_size,
             _output_buffer,
             _output_buffer_size,
             &_output_bytes_written)) != OE_OK)
        goto done;

    /* Set up output arg struct pointer */
    _pargs_out = (ecall_wstring_no_null_terminator_args_t*)_output_buffer;
    OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));

    /* Check if the call succeeded */
    if ((_result = _pargs_out->_result) != OE_OK)
        goto done;

    /* Currently exactly _output_buffer_size bytes must be written */
    if (_output_bytes_written != _output_buffer_size)
    {
        _result = OE_FAILURE;
        goto done;
    }

    /* Unmarshal return value and out, in-out parameters */
    OE_CHECK_NULL_TERMINATOR_WIDE(
        _output_buffer + _output_buffer_offset, _args.s2_len);
    OE_READ_IN_OUT_PARAM(s2, (size_t)(_args.s2_len * sizeof(wchar_t)));

    _result = OE_OK;
done:
    if (_buffer)
        free(_buffer);
    return _result;
}

void test_string_edl_ecalls(oe_enclave_t* enclave)
{
    const char* str_value = "Hello, World\n";

    char str[STR_LENGTH];
    sprintf_s(str, sizeof(str), "%s", str_value);

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
    sprintf_s(str, sizeof(str), "%s", str_value);

    // char* user check.
    OE_TEST(ecall_string_fun5(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, "Hello") == 0);

    // char* user check.
    OE_TEST(ecall_string_fun6(enclave, str) == OE_OK);
    OE_TEST(strcmp(str, "Hello") == 0);

    // Multiple string params. One null.
    OE_TEST(ecall_string_fun7(enclave, str, NULL) == OE_OK);

    // Test strings without null terminators.
    {
        char s1[] = "Hello";
        char s2[] = "Hello";

        // Call function with proper strings.
        OE_TEST(
            ecall_string_no_null_terminator_modified(enclave, s1, s2, 6, 6) ==
            OE_OK);

        // Pass s1 without null terminator
        OE_TEST(
            ecall_string_no_null_terminator_modified(enclave, s1, s2, 5, 6) ==
            OE_INVALID_PARAMETER);

        // Pass s2 without null terminator
        OE_TEST(
            ecall_string_no_null_terminator_modified(enclave, s1, s2, 6, 5) ==
            OE_INVALID_PARAMETER);
    }
    // Test wstrings without null terminators.
    {
        // wchar_t is not a portable type. Hence the test is performed
        // only on Linux.
#ifdef __linux__
        wchar_t s1[] = L"Hello";
        wchar_t s2[] = L"Hello";

        // Call function with proper strings.
        OE_TEST(
            ecall_wstring_no_null_terminator_modified(enclave, s1, s2, 6, 6) ==
            OE_OK);

        // Pass s1 without null terminator
        OE_TEST(
            ecall_wstring_no_null_terminator_modified(enclave, s1, s2, 5, 6) ==
            OE_INVALID_PARAMETER);

        // Pass s2 without null terminator
        OE_TEST(
            ecall_wstring_no_null_terminator_modified(enclave, s1, s2, 6, 5) ==
            OE_INVALID_PARAMETER);
#endif
    }

    printf("=== expect four OE_INVALID_PARAMETER errors above ===");
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
    OE_UNUSED(s);
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

void test_wstring_edl_ecalls(oe_enclave_t* enclave)
{
    const wchar_t* str_value = L"Hello, World\n";
    wchar_t str[STR_LENGTH];

    if (!g_enabled[TYPE_WCHAR_T])
        return;

    swprintf(str, sizeof(str) / sizeof(wchar_t), L"%lS", str_value);

    // wchar_t*
    OE_TEST(ecall_wstring_fun1(enclave, str) == OE_OK);
    OE_TEST(wcscmp(str, str_value) == 0);

    // const wchar_t*. (wchar_t* is passed in)
    OE_TEST(ecall_wstring_fun2(enclave, str) == OE_OK);
    OE_TEST(wcscmp(str, str_value) == 0);

    // wchar_t* in/out
    OE_TEST(ecall_wstring_fun3(enclave, str) == OE_OK);
    OE_TEST(wcscmp(str, L"Goodbye\n") == 0);

    // Restore value.
    swprintf(str, sizeof(str) / sizeof(wchar_t), L"%lS", str_value);

    // wchar_t* user check.
    OE_TEST(ecall_wstring_fun5(enclave, str) == OE_OK);
    OE_TEST(wcscmp(str, L"Hello") == 0);

    // wchar_t* user check.
    OE_TEST(ecall_wstring_fun6(enclave, str) == OE_OK);
    OE_TEST(wcscmp(str, L"Hello") == 0);

    // Multiple wstring params. One null.
    OE_TEST(ecall_wstring_fun7(enclave, str, NULL) == OE_OK);

    printf("=== test_string_edl_ecalls passed\n");
}

void ocall_wstring_fun1(wchar_t* s)
{
    ocall_wstring_fun1_args_t args;
    check_type<wchar_t*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    // strcmp should not crash.
    OE_TEST(wcscmp(s, L"Hello, World\n") == 0);
}

void ocall_wstring_fun2(const wchar_t* s)
{
    ocall_wstring_fun2_args_t args;
    // constness is discarded when marshaling.
    check_type<wchar_t*>(args.s);
    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    // strcmp should not crash.
    OE_TEST(wcscmp(s, L"Hello, World\n") == 0);
}

void ocall_wstring_fun3(wchar_t* s)
{
    ocall_wstring_fun3_args_t args;
    check_type<wchar_t*>(args.s);

    check_type<size_t>(args.s_len);

    // Check that s has been copied over.
    // strcmp should not crash.
    OE_TEST(wcscmp(s, L"Hello, World\n") == 0);

    // Write to s. Check on enclave side for new value.
    const wchar_t* new_s = L"Goodbye\n";
    memcpy(s, new_s, (wcslen(new_s) + 1) * sizeof(wchar_t));
}

void ocall_wstring_fun5(wchar_t* s)
{
    ocall_wstring_fun5_args_t args;
    check_type<wchar_t*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ocall_wstring_fun5_args_t>();

    // Change value to Hello.
    s[5] = L'\0';
}

void ocall_wstring_fun6(const wchar_t* s)
{
    OE_UNUSED(s);
    ocall_wstring_fun6_args_t args;
    // constness is discarded when marshaling.
    check_type<wchar_t*>(args.s);
    // User check implies no s_len field is created.
    assert_no_field_s_len<ocall_wstring_fun6_args_t>();
}

void ocall_wstring_fun7(wchar_t* s1, wchar_t* s2)
{
    ocall_wstring_fun7_args_t args;

    check_type<wchar_t*>(args.s1);
    check_type<size_t>(args.s1_len);
    check_type<wchar_t*>(args.s2);
    check_type<size_t>(args.s2_len);

    OE_TEST(s1 != NULL);
    OE_TEST(s2 == NULL);
}

void ocall_string_no_null_terminator(bool erasenull, char* s)
{
    size_t size = strlen(s);
    if (erasenull)
        s[size] = '?';
}

void ocall_wstring_no_null_terminator(bool erasenull, wchar_t* s)
{
    size_t size = wcslen(s);
    if (erasenull)
        s[size] = '?';
}
