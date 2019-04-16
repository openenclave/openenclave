// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/typeinfo.h>

static __inline__ uint64_t _align(uint64_t x)
{
    const uint64_t m = 16;
    return (x + m - 1) / m * m;
}

typedef struct _allocator
{
    uint8_t* data;
    size_t capacity;
    size_t offset;
} allocator_t;

static void _allocator_init(allocator_t* a, void* data, size_t capacity)
{
    a->capacity = capacity;
    a->data = data;
    a->offset = 0;
}

static void* _alloc(size_t size, void* a_)
{
    allocator_t* a = (allocator_t*)a_;
    void* ptr;

    if (!a)
        return NULL;

    size = _align(size);

    if (size > (a->capacity - a->offset))
        return NULL;

    ptr = a->data + a->offset;
    a->offset += size;

    return ptr;
}

static int _compute_count(
    const oe_struct_type_info_t* sti,
    const void* struct_ptr,
    const oe_field_type_info_t* field,
    const void* field_ptr,
    size_t* count_out)
{
    int ret = -1;
    size_t count = 0;

    *count_out = 0;

    if (field->count_offset == OE_SIZE_MAX)
    {
        if (field->count_value == OE_SIZE_MAX)
        {
            const char* str;

            if (field->elem_size != sizeof(char))
                goto done;

            if ((str = *((const char**)field_ptr)))
                count = oe_strlen(str) + 1;
        }
        else
        {
            count = field->count_value;
        }
    }
    else
    {
        const uint8_t* p = (const uint8_t*)struct_ptr + field->count_offset;

        /* Handle case where count is given by another field. */

        if (field->count_offset + field->count_value > sti->struct_size)
            goto done;

        switch (field->count_value)
        {
            case sizeof(uint8_t):
            {
                count = *((const uint8_t*)p);
                break;
            }
            case sizeof(uint16_t):
            {
                count = *((const uint16_t*)p);
                break;
            }
            case sizeof(uint32_t):
            {
                count = *((const uint32_t*)p);
                break;
            }
            case sizeof(uint64_t):
            {
                count = *((const uint64_t*)p);
                break;
            }
            default:
            {
                goto done;
            }
        }
    }

    if (count == 0)
        goto done;

    *count_out = count;

    ret = 0;

done:
    return ret;
}

static int _clone(
    const oe_struct_type_info_t* sti,
    const void* src,
    void* dest,
    void* (*alloc)(size_t size, void* alloc_data),
    void* alloc_data)
{
    int ret = -1;

    if (!sti || !src || !dest || !alloc)
        goto done;

    /* Initialize the destination memory. */
    memset(dest, 0, sti->struct_size);
    memcpy(dest, src, sti->struct_size);

    for (size_t i = 0; i < sti->num_fields; i++)
    {
        const oe_field_type_info_t* f = &sti->fields[i];
        const uint8_t* src_field = (const uint8_t*)src + f->field_offset;
        uint8_t* dest_field = (uint8_t*)dest + f->field_offset;
        size_t count;

        /* Verify that field is within sti boundaries. */
        if (f->field_offset + f->field_size > sti->struct_size)
            goto done;

        /* Skip over null pointer fields. */
        if (!*(void**)src_field)
            continue;

        /* Determine the count (the number of elements). */
        if (_compute_count(sti, src, f, src_field, &count) != 0)
            goto done;

        /* Copy this array field. */
        {
            uint8_t* data;
            size_t size = count * f->elem_size;

            /* Allocate memory for this array. */
            if (!(data = (*alloc)(size, alloc_data)))
                goto done;

            /* Assign the array field in the destination structure. */
            *((void**)dest_field) = data;

            const uint8_t* src_ptr = *((const uint8_t**)src_field);
            uint8_t* dest_ptr = *((uint8_t**)dest_field);

            /* Copy each element of this array. */
            for (size_t i = 0; i < count; i++)
            {
                if (f->sti)
                {
                    if (_clone(f->sti, src_ptr, dest_ptr, alloc, alloc_data) !=
                        0)
                    {
                        goto done;
                    }
                }
                else
                {
                    memcpy(dest_ptr, src_ptr, f->elem_size);
                }

                src_ptr += f->elem_size;
                dest_ptr += f->elem_size;
            }
        }
    }

    ret = 0;

done:
    return ret;
}

static int _compute_total_size(
    const oe_struct_type_info_t* sti,
    const void* src,
    size_t* size)
{
    int ret = -1;

    if (!sti || !src || !size)
        goto done;

    *size = _align(sti->struct_size);

    for (size_t i = 0; i < sti->num_fields; i++)
    {
        const oe_field_type_info_t* f = &sti->fields[i];
        const uint8_t* src_field = (const uint8_t*)src + f->field_offset;
        size_t count;

        /* Verify that field is within structure boundaries. */
        if (f->field_offset + f->field_size > sti->struct_size)
            goto done;

        /* Skip over null pointer fields. */
        if (!*(void**)src_field)
            continue;

        /* Determine the count (the number of elements). */
        if (_compute_count(sti, src, f, src_field, &count) != 0)
            goto done;

        /* Determine size of this array field and its descendents. */
        {
            if (f->sti)
            {
                const uint8_t* src_ptr = *((const uint8_t**)src_field);

                for (size_t i = 0; i < count; i++)
                {
                    size_t tmp_size;

                    if (_compute_total_size(f->sti, src_ptr, &tmp_size) != 0)
                        goto done;

                    *size += _align(tmp_size);

                    src_ptr += f->elem_size;
                }
            }
            else
            {
                *size += _align(count * f->elem_size);
            }
        }
    }

    ret = 0;

done:
    return ret;
}

oe_result_t oe_type_info_clone(
    const oe_struct_type_info_t* sti,
    const void* src,
    void* dest,
    size_t* dest_size_in_out)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t size;

    (void)dest;

    /* Check required parameters. */
    if (!sti || !src || !dest_size_in_out)
    {
        result = OE_UNEXPECTED;
        goto done;
    }

    /* Determine whether buffer is big enough. */
    {
        if (_compute_total_size(sti, src, &size) != 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        if (size > *dest_size_in_out)
        {
            *dest_size_in_out = size;
            result = OE_BUFFER_TOO_SMALL;
            goto done;
        }

        *dest_size_in_out = size;
    }

    /* Perform the deep copy. */
    if (dest)
    {
        allocator_t a;

        _allocator_init(&a, dest, size);

        a.offset = _align(sti->struct_size);

        if (_clone(sti, src, dest, _alloc, &a) != 0)
        {
            result = OE_FAILURE;
            goto done;
        }
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_type_info_update(
    const oe_struct_type_info_t* sti,
    const void* src,
    void* dest)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!sti || !src || !dest)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Update the heap objects. */
    for (size_t i = 0; i < sti->num_fields; i++)
    {
        const oe_field_type_info_t* fti = &sti->fields[i];
        const uint8_t* src_field = (const uint8_t*)src + fti->field_offset;
        const uint8_t* dest_field = (const uint8_t*)dest + fti->field_offset;
        size_t src_count;
        size_t dest_count;

        /* Verify that field is within structure boundaries. */
        if (fti->field_offset + fti->field_size > sti->struct_size)
            goto done;

        /* Skip over null pointer fields. */
        if (!*(void**)src_field && !*(void**)dest_field)
            continue;

        /* Fail if source field is null (and destination was not). */
        if (!*(void**)src_field)
        {
            result = OE_FAILURE;
            goto done;
        }

        /* Fail if destination field is null (and source was not). */
        if (!*(void**)dest_field)
        {
            result = OE_FAILURE;
            goto done;
        }

        /* Determine the size of the source heap object. */
        if (_compute_count(sti, src, fti, src_field, &src_count) != 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        /* Determine the size of the destination heap object. */
        if (_compute_count(sti, dest, fti, dest_field, &dest_count) != 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        /* If the destination is not big enough. */
        if (dest_count < src_count)
        {
            result = OE_FAILURE;
            goto done;
        }

        /* Update the destination heap object from the source. */
        {
            const uint8_t* src_ptr = *((const uint8_t**)src_field);
            uint8_t* dest_ptr = *((uint8_t**)dest_field);

            /* Copy each element of this array. */
            for (size_t i = 0; i < src_count; i++)
            {
                if (fti->sti)
                {
                    oe_result_t r;

                    r = oe_type_info_update(fti->sti, src_ptr, dest_ptr);

                    if (r != OE_OK)
                    {
                        result = r;
                        goto done;
                    }
                }
                else
                {
                    memcpy(dest_ptr, src_ptr, fti->elem_size);
                }

                src_ptr += fti->elem_size;
                dest_ptr += fti->elem_size;
            }
        }
    }

    /* Update any count fields. */
    for (size_t i = 0; i < sti->num_fields; i++)
    {
        const oe_field_type_info_t* fti = &sti->fields[i];

        if (fti->count_offset != OE_SIZE_MAX)
        {
            const uint8_t* src_field = (const uint8_t*)src + fti->count_offset;
            uint8_t* dest_field = (uint8_t*)dest + fti->count_offset;
            memcpy(dest_field, src_field, fti->count_value);
        }
    }

    result = OE_OK;

done:
    return result;
}
