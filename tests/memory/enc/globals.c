#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <stdlib.h>
#include <string.h>
#include "../args.h"

/* C static initialization defaults to the 0 / NULL type. */
static int defaultInt;
static float defaultFloat;
static int* defaultPtr;
static DummyStruct defaultStruct;
static DummyUnion defaultUnion;
static int defaultArray[4];

/* Explicit C static initialization. */
static int explicitInt = 1;
static float explicitFloat = 1.0;
static int* explicitPtr = (int*)0x1;
static DummyStruct explicitStruct = {1, 1};
static DummyUnion explicitUnion = {.y = 1};
static int explicitArray[4] = {1, 1, 1, 1};

OE_ECALL void GetGlobals(void* args)
{
    GlobalArgs* gargs = (GlobalArgs*)args;
    if (!gargs)
        return;

    if (gargs->getDefault)
    {
        gargs->globalInt = defaultInt;
        gargs->globalFloat = defaultFloat;
        gargs->globalPtr = defaultPtr;
        gargs->globalStruct = defaultStruct;
        gargs->globalUnion = defaultUnion;
        memcpy(
            gargs->globalArray, defaultArray, GLOBAL_ARRAY_SIZE * sizeof(int));
    }
    else
    {
        gargs->globalInt = explicitInt;
        gargs->globalFloat = explicitFloat;
        gargs->globalPtr = explicitPtr;
        gargs->globalStruct = explicitStruct;
        gargs->globalUnion = explicitUnion;
        memcpy(
            gargs->globalArray, explicitArray, GLOBAL_ARRAY_SIZE * sizeof(int));
    }
}

OE_ECALL void SetGlobals(void* args)
{
    GlobalArgs* gargs = (GlobalArgs*)args;
    if (!gargs)
        return;

    if (gargs->getDefault)
    {
        defaultInt = gargs->globalInt;
        defaultFloat = gargs->globalFloat;
        defaultPtr = gargs->globalPtr;
        defaultStruct = gargs->globalStruct;
        defaultUnion = gargs->globalUnion;
        memcpy(
            defaultArray, gargs->globalArray, GLOBAL_ARRAY_SIZE * sizeof(int));
    }
    else
    {
        explicitInt = gargs->globalInt;
        explicitFloat = gargs->globalFloat;
        explicitPtr = gargs->globalPtr;
        explicitStruct = gargs->globalStruct;
        explicitUnion = gargs->globalUnion;
        memcpy(
            explicitArray, gargs->globalArray, GLOBAL_ARRAY_SIZE * sizeof(int));
    }
}
