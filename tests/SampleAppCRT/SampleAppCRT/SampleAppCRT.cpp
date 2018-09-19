// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define OE_OCALL_FAILED -1

static uint32_t func()
{
    static int state = 0;

    if (state < 2)
        ++state;

    return state;
}

int globalStatic = 1;
int globalDynamic = func();
uint32_t threadLocalStatic = 2;
uint32_t threadLocalDynamic = func();
char asciistring[] = "HelloWorld";
wchar_t wcstring[] = L"HelloWorld";

OE_ECALL int Test(void* args)
{
    int* returnValuePtr = (int*)args;

#if 1
    if (!oe_is_outside_enclave(returnValuePtr, sizeof(int)))
    {
        return OE_OCALL_FAILED;
    }
#endif

#if 0
    if (threadLocalStatic != GetCurrentThreadId())
    {
        *returnValuePtr = -1;
        return;
    }
#endif

    void* tempRegion = malloc(1);
    if (tempRegion == NULL)
    {
        *returnValuePtr = -2;
        return OE_OK;
    }
    tempRegion = realloc(tempRegion, sizeof(asciistring));
    if (tempRegion == NULL)
    {
        *returnValuePtr = -3;
        return OE_OK;
    }

    wcstombs((char*)tempRegion, wcstring, wcslen(wcstring));
    ((char*)tempRegion)[wcslen(wcstring)] = '\0';
    if (strcmp(asciistring, (char*)tempRegion) != 0)
    {
        *returnValuePtr = -4;
        return OE_OK;
    }

    memset(tempRegion, 0, sizeof(asciistring));
    snprintf((char*)tempRegion, sizeof(asciistring), "%s", asciistring);
    if (strcmp(asciistring, (char*)tempRegion) != 0)
    {
        *returnValuePtr = -5;
        return OE_OK;
    }

    tempRegion = realloc(tempRegion, sizeof(wcstring));
    if (tempRegion == NULL)
    {
        *returnValuePtr = -6;
        return OE_OK;
    }

    mbstowcs((wchar_t*)tempRegion, asciistring, strlen(asciistring));
    ((wchar_t*)tempRegion)[strlen(asciistring)] = '\0';

#ifndef OE_SIM
    /* Broken in MUSL library */
    if (wcscmp(wcstring, (wchar_t*)tempRegion) != 0)
    {
        *returnValuePtr = -7;
        return OE_OK;
    }
#endif

    free(tempRegion);

    *returnValuePtr = 0;
    return OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */
