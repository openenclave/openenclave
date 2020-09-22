// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_DEBUG_MALLOC_H
#define _OE_DEBUG_MALLOC_H

#include <openenclave/bits/result.h>

#ifdef __cplusplus
extern "C"
{
#endif

    oe_result_t oe_debug_malloc_tracking_start(void);

    oe_result_t oe_debug_malloc_tracking_stop(void);

    oe_result_t oe_debug_malloc_tracking_report(
        uint64_t* out_num_objects,
        char** report);

#ifdef __cplusplus
}
#endif

#endif /* _OE_DEBUG_MALLOC_H */
