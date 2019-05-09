// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_RESERVE_H
#define _OE_INTERNAL_RESERVE_H

#include <openenclave/bits/types.h>

/**
 * Increases the capacity of a dynamic array.
 *
 * This function increases the capacity of the dynamic array pointed to by
 * **array**. The capacity is increased to **new_capacity**. The first **size**
 * elements of the array are preserved. The remaining elements if any are
 * filled with zeros. The **capacity** indicates how many elements are
 * allocated, whereas the **size** indicates how many elements are in use.
 * The **size** must be less than or equal to the **capacity**.
 *
 * @param array pointer to heap allocated memory (may be null if size is zero).
 * @param size the number of elements in the array (size <= capacity).
 * @param elem_size the size of a single element.
 * @param capacity the current capacity of the array (capacity >= size).
 * @param new_capacity the requested new capacity of the array.
 *
 * @return 0 upon success.
 * @return -1 on failure.
 */
int oe_reserve(
    void** array,
    size_t size,
    size_t elem_size,
    size_t* capacity,
    size_t new_capacity);

#endif /* _OE_INTERNAL_RESERVE_H */
