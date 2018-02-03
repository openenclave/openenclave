#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openenclave/enclave.h>

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

OE_ECALL void Test(void* args)
{
    int* returnValuePtr = (int*)args;

#if 1
    if (!OE_IsOutsideEnclave(returnValuePtr, sizeof(int)))
    {
        return;
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
        return;
    }
    tempRegion = realloc(tempRegion, sizeof(asciistring));
    if (tempRegion == NULL)
    {
        *returnValuePtr = -3;
        return;
    }

    wcstombs((char*)tempRegion, wcstring, wcslen(wcstring));
    if (strcmp(asciistring, (char*)tempRegion) != 0)
    {
        *returnValuePtr = -4;
        return;
    }

    memset(tempRegion, 0, sizeof(asciistring));
    snprintf((char*)tempRegion, sizeof(asciistring), "%s", asciistring);
    if (strcmp(asciistring, (char*)tempRegion) != 0)
    {
        *returnValuePtr = -5;
        return;
    }

    tempRegion = realloc(tempRegion, sizeof(wcstring));
    if (tempRegion == NULL)
    {
        *returnValuePtr = -6;
        return;
    }

    memset(tempRegion, 0, sizeof(wcstring));

    mbstowcs((wchar_t*)tempRegion, asciistring, strlen(asciistring));

#ifndef OE_SIM
    /* Broken in MUSL library */
    if (wcscmp(wcstring, (wchar_t*)tempRegion) != 0)
    {
        *returnValuePtr = -7;
        return;
    }
#endif
    
    free(tempRegion);

    *returnValuePtr = 0;
}
