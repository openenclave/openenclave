// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TYPEINFO_H
#define _OE_TYPEINFO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_SIZEOF(TYPE, MEMBER) (sizeof(((((TYPE*)0)->MEMBER))))

// clang-format off
#define OE_FTI_STRING(STRUCT, FIELD)                \
    {                                               \
        .field_offset = OE_OFFSETOF(STRUCT, FIELD), \
        .field_size = OE_SIZEOF(STRUCT, FIELD),     \
        .elem_size = sizeof(char),                  \
        .count_offset = OE_SIZE_MAX,                \
        .count_value = OE_SIZE_MAX,                 \
    }
// clang-format on

// clang-format off
#define OE_FTI_STRUCTS(STRUCT, FIELD, STRUCT2, COUNT_FIELD, STI) \
    {                                                            \
        .field_offset = OE_OFFSETOF(STRUCT, FIELD),              \
        .field_size = OE_SIZEOF(STRUCT, FIELD),                  \
        .elem_size = sizeof(STRUCT2),                            \
        .count_offset = OE_OFFSETOF(STRUCT, COUNT_FIELD),        \
        .count_value = OE_SIZEOF(STRUCT, COUNT_FIELD),           \
        .sti = STI                                               \
    }
// clang-format on

// clang-format off
#define OE_FTI_STRUCT(STRUCT, FIELD, STRUCT2, STI)  \
    {                                               \
        .field_offset = OE_OFFSETOF(STRUCT, FIELD), \
        .field_size = OE_SIZEOF(STRUCT, FIELD),     \
        .elem_size = sizeof(STRUCT2),               \
        .count_offset = OE_SIZE_MAX,                \
        .count_value = 1,                           \
        .sti = STI                                  \
    }
// clang-format on

// clang-format off
#define OE_FTI_ARRAY(STRUCT, FIELD, ELEM_SIZE, COUNT_FIELD) \
    {                                                       \
        .field_offset = OE_OFFSETOF(STRUCT, FIELD),         \
        .field_size = OE_SIZEOF(STRUCT, FIELD),             \
        .elem_size = ELEM_SIZE,                             \
        .count_offset = OE_OFFSETOF(STRUCT, COUNT_FIELD),   \
        .count_value = OE_SIZEOF(STRUCT, COUNT_FIELD),      \
    }
// clang-format on

struct _oe_struct_type_info;

/* This structure provides type information for a pointer field within a
 * structure.
 */
typedef struct _oe_field_type_info
{
    /* The byte offset of this field within the structure. */
    size_t field_offset;

    /* The size of this field within the structure. */
    size_t field_size;

    /* This size of one element */
    size_t elem_size;

    /* If count_offset == SIZE_MAX:
     *     count_value contains the count.
     * Else:
     *     count_offset is the offset of the integer field containing the count.
     */
    size_t count_offset;

    /* If count_offset == SIZE_MAX:
     *     count_value contains the count. If this count is SIZE_MAX then
     *     the field is a zero-terminated string.
     * Else:
     *     count_value is the size of the integer field containing the count.
     */
    size_t count_value;

    /* The strut type information for this field. */
    const struct _oe_struct_type_info* sti;

} oe_field_type_info_t;

/* This structure provides type information for a structure definition.
 */
typedef struct _oe_struct_type_info
{
    size_t struct_size;
    const oe_field_type_info_t* fields;
    size_t num_fields;
} oe_struct_type_info_t;

/**
 * Clone a structure onto a memory buffer.`
 *
 * This function performs a deep clone of the source structure (**src**), which
 * includes all heap objects reachable from the structure. The destination
 * buffer must be large enough to contain this result. To determine the
 * required destination size, call this function with **dest** set to null
 * **dest_size_in_out** set to zero.
 *
 * Note: this function does not handle cycles.
 *
 * @param sti the structure type information of **src** and **dest**.
 * @param src the source structure that will be deep copied.
 * @param dest the destination structure that will contain the result (may be
 *        null to determine size requirements).
 * @param dest_size_in_out size **dest** buffer on input. The required size
 *        on output.
 *
 * @return OE_OK success
 * @return OE_FAILURE the operation failed.
 * @return OE_BUFFER_TOO_SMALL the **dest** buffer is too small and
 *         upon return, **dest_size_in_out** contains the required size.
 *
 */
oe_result_t oe_type_info_clone(
    const oe_struct_type_info_t* sti,
    const void* src,
    void* dest,
    size_t* dest_size_in_out);

/**
 * Use the source structure to update the destination structure.
 *
 * This function updates fields in the destination structure from fields
 * in the source structure. It does not require any additional destination
 * memory, since all heap objects reachable from the source structure are the
 * same size or smaller than the corresponding heap objects in the destination
 * structure (that is the source and destination structures have the same shape
 * on the heap). As an example, consider the following
 * structure.
 *
 *     ```
 *     struct my_struct
 *     {
 *         uint8_t* data;
 *         size_t datalen;
 *     };
 *     .
 *     .
 *     .
 *     const struct my_struct* src;
 *     struct my_struct* dest;
 *     ```
 *
 * In this example, the following conditions must hold, else an error is
 * returned.
 *
 *     - The size of the **src->data** buffer must be less than or equal to the
 *       size of the **dest->data** buffer.
 *     - The value of **src->datalen** is less than or equal to
 *       **dest->datalen**.
 *
 * For these fields, this function performs two operations:
 *
 *     - Copies **src->datalen** bytes from **src->data** to **dest->data**.
 *     - Sets **dest->datalen** to **src->datalen**.
 *
 * @param sti the structure type information of **src** and **dest**.
 * @param src the source structure.
 * @param dest the destination structure.
 *
 * @return OE_OK success
 * @return OE_FAILURE the operation failed.
 *
 */
oe_result_t oe_type_info_update(
    const oe_struct_type_info_t* sti,
    const void* src,
    void* dest);

OE_EXTERNC_END

#endif /* _OE_TYPEINFO_H */
