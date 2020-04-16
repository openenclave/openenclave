// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../dynload.h"
#include <dlfcn.h>

void* oe_shared_library_load(const char* name)
{
    return dlopen(name, RTLD_LAZY | RTLD_LOCAL);
}

void oe_shared_library_unload(void* handle)
{
    dlclose(handle);
}

void* oe_shared_library_lookup(void* handle, const char* function)
{
    return dlsym(handle, function);
}
