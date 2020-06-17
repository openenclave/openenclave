// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_FILES_H
#define _OE_FILES_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <stdio.h>
#include "types.h"

OE_EXTERNC_BEGIN

bool __oe_file_exists(const char* path);

oe_result_t __oe_load_file(
    const char* path,
    size_t extra_bytes,
    void** data,
    size_t* size);

oe_result_t __oe_load_pages(
    const char* path,
    oe_page_t** pages,
    size_t* npages);

OE_EXTERNC_END

#endif /* _OE_FILES_H */
