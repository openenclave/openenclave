// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_MODULE_H
#define _OE_INTERNAL_MODULE_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_enclave_module_info
{
    /* The RVA of the module's base address. Being zero indicates that
     * the no module is present. */
    uint64_t base_rva;
    /* Variables used to locate initialization functions. Being zero
     * indicates that the module does not implement such functions. */
    uint64_t init_array_rva;
    uint64_t init_array_size;
    /* Variables used to locate termination functions. Being zero
     * indicates that the module does not implement such functions. */
    uint64_t fini_array_rva;
    uint64_t fini_array_size;
} oe_enclave_module_info_t;

OE_EXTERNC_END

#endif // _OE_INTERNAL_MODULE_H
