// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_DYNLOAD_H
#define _OE_HOST_DYNLOAD_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

void* oe_shared_library_load(const char* name);
void oe_shared_library_unload(void* handle);
void* oe_shared_library_lookup(void* handle, const char* function);

OE_EXTERNC_END

#endif /* _OE_HOST_DUPENV_H */
