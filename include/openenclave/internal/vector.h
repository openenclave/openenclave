// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_VECTOR_H
#define _OE_INTERNAL_VECTOR_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_vector
{
    void* data;
    size_t size;
} oe_vector_t;

/**
 * Pack a vector array into a flat representation.
 *
 * This function packs an array of vector structures onto a flat buffer.
 * Consider the following definition.
 *
 *     ```
 *     oe_vector_t vectors[] =
 *     {
 *         { "red", 4 },
 *         { "green", 6 },
 *         { "blue", 5 },
 *     };
 *     size_t vector_count = sizeof(vectors) / sizeof(vectors[0]);
 *     ```
 *
 * This is packed with the following call.
 *
 *     ```
 *     void* buf;
 *     size_t buf_size;
 *     oe_vector_pack(vectors, vector_count, &buf, &buf_size);
 *     ```
 *
 * The buffer layout for this example is shown below.
 *
 *     ```
 *     [OFFSET0][4]                vector[0]
 *     [OFFSET1][6]                vector[1]
 *     [OOFSET2][5]                vector[2]
 *     [red\0green\0blue\0]
 *     ```
 *
 * Or more compactly:
 *
 *     ```
 *     [3][OFFSET0][4][OFFSET1][6][OFFSET2][5][red\0green\0blue\0]
 *     ```
 *
 * The **oe_vector_t.data** pointers are translated into integer offsets from
 * the base of the buffer. For example, OFFSET1 is the offset of "green"
 * relative to the start of the buffer.
 *
 * The translation of pointers to offsets makes the buffer position-independent.
 * This means the buffer can be moved or transmitted to another process or
 * address space where the offsets can be relocated (**oe_vector_relocate()**).
 *
 */
oe_result_t oe_vector_pack(
    const oe_vector_t* vectors,
    size_t vector_count,
    void** buf_out,
    size_t* buf_size_out,
    void* (*malloc)(size_t),
    void (*free)(void*));

/**
 * Relocate a vector array that was packed with **oe_vector_pack**.
 *
 * This function relocates the **oe_vector_t.data** elements of a packed
 * vector. It returns a pointer to the relocated vector.
 */
oe_vector_t* oe_vector_relocate(void* buf, size_t vector_count);

/**
 * Convert a vector array to an argv-style string array.
 */
char** oe_vector_to_argv(
    const oe_vector_t* vector,
    size_t size,
    void* (*malloc)(size_t),
    void (*free)(void*));

OE_EXTERNC_END

#endif /* _OE_INTERNAL_VECTOR_H */
