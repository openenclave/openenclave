// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../dynload.h"
#include <Windows.h>

void* oe_shared_library_load(const char* name)
{
    return (void*)LoadLibraryEx(name, NULL, 0);
}

void oe_shared_library_unload(void* handle)
{
    FreeLibrary((HANDLE)handle);
}

void* oe_shared_library_lookup(void* handle, const char* function)
{
    return (void*)GetProcAddress((HANDLE)handle, function);
}
