// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mbed_u.h"

char* find_data_file(char* str, size_t size)
{
    char* tail = ".data";
    char* checker = "test_suite_";
    char* token;

    if (size < strlen(str) + strlen(tail) + 1)
    {
        printf("buffer overflow error");
        return NULL;
    }
    token = strstr(str, checker);
    if (token == NULL)
    {
        printf("!!File is not in format !!!!\n");
        return token;
    }

    strncat(str, tail, strlen(tail));
    printf("######## data_file: %s ###### \n", token);
    return token;
}

void datafileloc(char* data_file_name, char* path)
{
    char* tail = "3rdparty/mbedtls/mbedtls/tests/suites/";
#ifdef PROJECT_DIR
    strcpy(path, PROJECT_DIR);
#else
    char* separator;

    if (getcwd(path, 1024) != NULL)
        fprintf(stdout, "Current working dir: %s\n", path);
    else
        perror("getcwd() error");
    separator = strstr(
        path, "build"); /* Find address at which string to be separated */
    if (separator == NULL)
    {
        printf("\n separator doesn't get the address\n");
    }

    *separator = '\0'; /* separating string */
#endif
    strcat(path, tail);
    strcat(path, data_file_name);

    printf("######## data_fileloc: %s ###### \n", path);
    return;
}

void Test(oe_enclave_t* enclave, int selftest, char* data_file_name)
{
    char path[1024];
    int return_value = 1;
    char* in_testname = NULL;
    char out_testname[STRLEN];
    struct mbed_args args = {0};
    if (!selftest)
    {
        datafileloc(data_file_name, path);
        in_testname = path;
    }

    oe_result_t result =
        test(enclave, &return_value, in_testname, out_testname, &args);
    OE_TEST(result == OE_OK);
    if (!selftest)
    {
        OE_TEST(args.total > 0);
        OE_TEST(args.total > args.skipped);
    }

    if (return_value == 0)
    {
        printf("PASSED: %s\n", out_testname);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", out_testname, return_value);
        abort();
    }
}

void ocall_exit(int arg)
{
    exit(arg);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    char temp[500];
    oe_enclave_t* enclave = NULL;
    int selftest = 0;
    uint32_t flags = oe_get_create_flags();
    char* data_file_name = NULL;
    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

    strcpy(temp, argv[1]);

    if (strstr(argv[1], "selftest"))
    {
        selftest = 1;
    }
    else
    {
        selftest = 0;

        data_file_name = find_data_file(temp, sizeof(temp));
        if (data_file_name == NULL)
        {
            printf("Could not get test data file name from %s\n", temp);
            return 0;
        }

        printf(
            "###after find_data_file call data_file_name is : %s\n",
            data_file_name);
    }

    // Create the enclave:
    if ((result = oe_create_mbed_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    // Invoke "Test()" in the enclave.
    Test(enclave, selftest, data_file_name);

    // Shutdown the enclave.
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);

    printf("\n");

    return 0;
}
