// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_FILES_H
#define _OE_FILES_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include <stdio.h>

OE_EXTERNC_BEGIN

bool __oe_file_exists(const char* path);

oe_result_t __oe_load_file(
    const char* path,
    size_t extraBytes,
    void** data,
    size_t* size);

oe_result_t __oe_load_pages(const char* path, oe_page** pages, size_t* npages);

OE_EXTERNC_END

#endif /* _OE_FILES_H */
