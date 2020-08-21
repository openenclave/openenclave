// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_LINK_H
#define _OE_LINK_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_module_link_info
{
    uint64_t base_rva;

    // TODO: Update td_init to use these values.
    uint64_t tdata_rva;
    uint64_t tdata_size;
    uint64_t tdata_align;
    uint64_t tbss_size;
    uint64_t tbss_align;

    // Init and fini sections.
    // TODO: Do we need preinit section?
    uint64_t init_array_rva;
    uint64_t init_array_size;
    uint64_t fini_array_rva;
    uint64_t fini_array_size;

} oe_module_link_info_t;

OE_EXTERNC_END

#endif // _OE_LINK_H
