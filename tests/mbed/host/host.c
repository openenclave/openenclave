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

typedef struct _Args
{
    char* test;
    int ret;
} Args;

char* find_data_file(char* str)
{
    char* dil = ".signed.so";
    char* tail = ".data";
    char* checker = "test_suite_";
    char *token, *temp;

    token = strstr(str, checker);
    if (token == NULL)
    {
        printf("!!File is not in format !!!!\n");
        return token;
    }
    temp = strstr((token), dil);
    if (temp == NULL)
    {
        return temp;
    }
    strcpy(temp, tail);
    printf("######## data_file: %s ###### \n", token);
    return token;
}

void datafileloc(char* data_file_name, char* path)
{
    char* tail = "3rdparty/mbedtls/mbedtls/tests/suites/";
    char* seperator;

    if (getcwd(path, 1024) != NULL)
        fprintf(stdout, "Current working dir: %s\n", path);
    else
        perror("getcwd() error");
    seperator = strstr(
        path, "build"); /* Find address at which string to be separated */
    if (seperator == NULL)
    {
        printf("\n seperator doesn't get the address\n");
    }

    *seperator = '\0'; /* separating string */
    strcat(path, tail);
    strcat(path, data_file_name);

    printf("######## data_fileloc: %s ###### \n", path);
    return;
}

void Test(oe_enclave_t* enclave, int selftest, char* data_file_name)
{
    char path[1024];
    Args args;
    args.ret = 1;
    args.test = NULL;

    if (!selftest)
    {
        datafileloc(data_file_name, path);
        args.test = path;
    }

    oe_result_t result = oe_call_enclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);

    if (args.ret == 0)
    {
        printf("PASSED: %s\n", args.test);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", args.test, args.ret);
        abort();
    }
}

OE_OCALL void ocall_exit(uint64_t arg)
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
    char* data_file_name;
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

        data_file_name = find_data_file(temp);
        if (data_file_name == NULL)
        {
            printf("!!!!! it is not sighned.so file !!!! \n");
            return 0;
        }

        printf(
            "###after find_data_file call data_file_name is : %s\n",
            data_file_name);
    }

    // Create the enclave:
    if ((result = oe_create_enclave(
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
