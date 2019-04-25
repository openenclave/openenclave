// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/print.h>

int oe_array_initialize(
    oe_array_t* array,
    size_t element_size,
    size_t chunk_size)
{
    int ret = -1;

    if (!array || !element_size || !chunk_size)
        goto done;

    memset(array, 0, sizeof(oe_array_t));
    array->element_size = element_size;
    array->chunk_size = chunk_size;

    ret = 0;

done:
    return ret;
}

void oe_array_free(oe_array_t* array)
{
    if (array)
    {
        oe_free(array->data);
        memset(array, 0, sizeof(oe_array_t));
    }
}

void oe_array_clear(oe_array_t* array)
{
    if (array)
        array->size = 0;
}

int oe_array_reserve(oe_array_t* array, size_t capacity)
{
    int ret = -1;

    if (!array || !capacity)
        goto done;

    if (capacity > array->capacity)
    {
        uint8_t* new_data;
        size_t new_capacity;

        /* Double current capacity (will be zero the first time) */
        new_capacity = array->capacity * 2;

        /* If capacity still insufficent, round to multiple of chunk size */
        if (capacity > new_capacity)
        {
            const size_t N = array->chunk_size;
            new_capacity = (capacity + N - 1) / N * N;
        }

        /* Expand allocation */
        {
            size_t alloc_size = new_capacity * array->element_size;

            if (!(new_data = oe_realloc(array->data, alloc_size)))
            {
                goto done;
            }
        }

        array->data = new_data;
        array->capacity = new_capacity;
    }

    ret = 0;

done:
    return ret;
}

int oe_array_resize(oe_array_t* array, size_t new_size)
{
    int ret = -1;

    if (!array)
        goto done;

    if (new_size > array->capacity)
    {
        if (oe_array_reserve(array, new_size) != 0)
            goto done;
    }

    if (new_size > array->size)
    {
        void* ptr = array->data + (array->size * array->element_size);
        size_t memset_size = (new_size - array->size) * array->element_size;
        memset(ptr, 0, memset_size);
    }

    array->size = new_size;

    ret = 0;

done:
    return ret;
}

int oe_array_append(oe_array_t* array, const void* element)
{
    int ret = -1;
    void* ptr;
    size_t index;

    if (!array || !element)
        goto done;

    if (oe_array_reserve(array, array->size + 1) != 0)
        goto done;

    index = array->size++;

    if (!(ptr = oe_array_get(array, index)))
    {
        array->size--;
        goto done;
    }

    memcpy(ptr, element, array->element_size);

    ret = 0;

done:
    return ret;
}

void* oe_array_get(oe_array_t* array, size_t index)
{
    void* ret = NULL;

    if (!array || index >= array->size)
        goto done;

    ret = array->data + (index * array->element_size);

done:
    return ret;
}

int oe_array_set(oe_array_t* array, size_t index, const void* element)
{
    int ret = -1;
    void* ptr;

    if (!element || !(ptr = oe_array_get(array, index)))
        goto done;

    memcpy(ptr, element, array->element_size);

    ret = 0;

done:
    return ret;
}
