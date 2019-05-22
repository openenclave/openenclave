// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/defs.h>

void* dlopen(const char* filename, int flags)
{
    OE_UNUSED(filename);
    OE_UNUSED(flags);
    return NULL;
}

int dlclose(void* handle)
{
    OE_UNUSED(handle);
    return 22;
}

char* dlerror(void)
{
    return "Not supported.";
}

void* dlsym(void* handle, const char* symbol)
{
    OE_UNUSED(handle);
    OE_UNUSED(symbol);
    return NULL;
}
