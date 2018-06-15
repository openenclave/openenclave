// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static uint32_t func()
{
    static int state = 0;

    if (state < 2)
        ++state;

    return state;
}

int global_static = 1;
int global_dynamic = func();
uint32_t thread_local_static = 2;
uint32_t thread_local_dynamic = func();
char asciistring[] = "HelloWorld";
wchar_t wcstring[] = L"HelloWorld";

OE_ECALL oe_result_t Test(void* args)
{
    int* return_value_ptr = (int*)args;

#if 1
    if (!oe_is_outside_enclave(return_value_ptr, sizeof(int)))
    {
        return OE_OCALL_FAILED;
    }
#endif

#if 0
    if (thread_local_static != GetCurrentThreadId())
    {
        *return_value_ptr = -1;
        return;
    }
#endif

    void* temp_region = malloc(1);
    if (temp_region == NULL)
    {
        *return_value_ptr = -2;
        return OE_OK;
    }
    temp_region = realloc(temp_region, sizeof(asciistring));
    if (temp_region == NULL)
    {
        *return_value_ptr = -3;
        return OE_OK;
    }

    wcstombs((char*)temp_region, wcstring, wcslen(wcstring));
    if (strcmp(asciistring, (char*)temp_region) != 0)
    {
        *return_value_ptr = -4;
        return OE_OK;
    }

    memset(temp_region, 0, sizeof(asciistring));
    snprintf((char*)temp_region, sizeof(asciistring), "%s", asciistring);
    if (strcmp(asciistring, (char*)temp_region) != 0)
    {
        *return_value_ptr = -5;
        return OE_OK;
    }

    temp_region = realloc(temp_region, sizeof(wcstring));
    if (temp_region == NULL)
    {
        *return_value_ptr = -6;
        return OE_OK;
    }

    mbstowcs((wchar_t*)temp_region, asciistring, strlen(asciistring));

#ifndef OE_SIM
    /* Broken in MUSL library */
    if (wcscmp(wcstring, (wchar_t*)temp_region) != 0)
    {
        *return_value_ptr = -7;
        return OE_OK;
    }
#endif

    free(temp_region);

    *return_value_ptr = 0;
    return OE_OK;
}
