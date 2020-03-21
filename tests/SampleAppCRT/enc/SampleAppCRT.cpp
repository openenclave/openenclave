// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "SampleAppCRT_t.h"

static int func()
{
    static int state = 0;

    if (state < 2)
        ++state;

    return state;
}

int global_static = 1;
int global_dynamic = func();
uint32_t thread_local_static = 2;
int32_t thread_local_dynamic = func();
char asciistring[] = "HelloWorld";
wchar_t wcstring[] = L"HelloWorld";

int enc_test()
{
#if 0
    if (thread_local_static != GetCurrentThreadId())
    {
        return -1;
    }
#endif

    void* temp_region = malloc(1);
    void* temp_region_2 = NULL;
    if (temp_region == NULL)
    {
        return -2;
    }

    temp_region_2 = realloc(temp_region, sizeof(asciistring));
    if (temp_region_2 == NULL)
    {
        free(temp_region);
        return -3;
    }
    else
    {
        temp_region = temp_region_2;
    }

    wcstombs((char*)temp_region, wcstring, wcslen(wcstring));
    ((char*)temp_region)[wcslen(wcstring)] = '\0';
    if (strcmp(asciistring, (char*)temp_region) != 0)
    {
        free(temp_region);
        return -4;
    }

    memset(temp_region, 0, sizeof(asciistring));
    snprintf((char*)temp_region, sizeof(asciistring), "%s", asciistring);
    if (strcmp(asciistring, (char*)temp_region) != 0)
    {
        free(temp_region);
        return -5;
    }

    temp_region_2 = realloc(temp_region, sizeof(wcstring));
    if (temp_region_2 == NULL)
    {
        free(temp_region);
        return -6;
    }
    else
    {
        temp_region = temp_region_2;
    }

    mbstowcs((wchar_t*)temp_region, asciistring, strlen(asciistring));
    ((wchar_t*)temp_region)[strlen(asciistring)] = '\0';

#ifndef OE_SIM
    /* Broken in MUSL library */
    if (wcscmp(wcstring, (wchar_t*)temp_region) != 0)
    {
        free(temp_region);
        return -7;
    }
#endif

    free(temp_region);
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */

#define TA_UUID                                            \
    { /* 31c4ecec-b94a-432a-ab76-4df401b6ee59 */           \
        0x31c4ecec, 0xb94a, 0x432a,                        \
        {                                                  \
            0xab, 0x76, 0x4d, 0xf4, 0x01, 0xb6, 0xee, 0x59 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1024 * 4096,
    256 * 4096,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "SampleAppCRT test");
