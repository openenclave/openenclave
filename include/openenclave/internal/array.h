// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_ARRAY_H
#define _OE_INTERNAL_ARRAY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

typedef struct _oe_array
{
    /* A pointer to the dynamically allocated array (may be null). */
    uint8_t* data;

    /* The current number of array elements. */
    size_t size;

    /* The capacity of the array (greater or equal to size). */
    size_t capacity;

    /* The size of a single array element. */
    size_t element_size;

    /* The number of array elements by which to grow the allocation. */
    size_t chunk_size;
} oe_array_t;

// clang-format off
#define OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE) \
    {                                                  \
        NULL,                                          \
        0,                                             \
        0,                                             \
        ELEMENT_SIZE,                                  \
        CHUNK_SIZE,                                    \
    }
// clang-format on

int oe_array_initialize(
    oe_array_t* array,
    size_t element_size,
    size_t chunk_size);

void oe_array_free(oe_array_t* array);

void oe_array_clear(oe_array_t* array);

int oe_array_reserve(oe_array_t* array, size_t capacity);

int oe_array_resize(oe_array_t* array, size_t new_size);

int oe_array_append(oe_array_t* array, const void* element);

void* oe_array_get(oe_array_t* array, size_t index);

int oe_array_set(oe_array_t* array, size_t index, const void* element);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_ARRAY_H */
