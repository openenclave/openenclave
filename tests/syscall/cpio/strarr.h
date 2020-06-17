// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_STRARR_H
#define _OE_STRARR_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

#define OE_STRARR_INITIALIZER \
    {                         \
        NULL, 0, 0            \
    }

OE_EXTERNC_BEGIN

typedef struct _oe_strarr
{
    char** data;
    size_t size;
    size_t capacity;
} oe_strarr_t;

void oe_strarr_release(oe_strarr_t* self);

int oe_strarr_append(oe_strarr_t* self, const char* data);

int oe_strarr_remove(oe_strarr_t* self, size_t index);

void oe_strarr_sort(oe_strarr_t* self);

OE_EXTERNC_END

#endif /* _OE_STRARR_H */
