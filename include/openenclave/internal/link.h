// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_LINK_H
#define _OE_LINK_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

OE_EXTERNC_BEGIN

typedef struct _oe_module_link_info
{
    /* Module image rva */
    uint64_t base_rva;

    /* Dynamic relocation info .rela.dyn section */
    uint64_t reloc_rva;
    uint64_t reloc_size;

    /* Thread-local storage .tdata section */
    uint64_t tdata_rva;
    uint64_t tdata_size;
    uint64_t tdata_align;

    /* Thread-local storage .tbss section */
    uint64_t tbss_size;
    uint64_t tbss_align;

    /* Global initialization .init_array section */
    uint64_t init_array_rva;
    uint64_t init_array_size;

    /* Global destructors .fini_array section */
    uint64_t fini_array_rva;
    uint64_t fini_array_size;

} oe_module_link_info_t;

/* thread-local management functions shared by host and enclave */
OE_INLINE size_t oe_module_has_tls(const oe_module_link_info_t* link_info)
{
    return (link_info->tdata_size || link_info->tbss_size);
}

OE_INLINE int64_t oe_get_module_tls_start_offset(
    const oe_module_link_info_t* link_info,
    int64_t previous_module_tls_start_offset)
{
    // Previous module's start is the current module's end.
    int64_t tls_end = previous_module_tls_start_offset;

    if (oe_module_has_tls(link_info))
    {
        // Choose the maximum of the two alignments. This is consistent with
        // PT_TLS program header that has a single alignment value (the
        // maximum).
        uint64_t alignment = link_info->tdata_align;
        if (link_info->tbss_align > alignment)
            alignment = link_info->tbss_align;

        // Round down the end to multiple of alignment. We round down because
        // current module's tls will lie *before* the previous module's tls.
        // Rounding down makes sure that current module's tls will not overlap
        // previous module's tls due to alignment/rounding.
        tls_end = (tls_end / (int64_t)alignment) * (int64_t)alignment;

        size_t tls_size =
            oe_round_up_to_multiple(link_info->tdata_size, alignment) +
            oe_round_up_to_multiple(link_info->tbss_size, alignment);

        return tls_end - (int64_t)tls_size;
    }

    return tls_end;
}

OE_EXTERNC_END

#endif // _OE_LINK_H
