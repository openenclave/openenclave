// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RANDOM_H
#define _OE_RANDOM_H

#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/**
 * Generate a sequence of random bytes.
 *
 * This function generates a sequence of random bytes.
 *
 * @param data the buffer that will be filled with random bytes
 * @param size the size of the buffer
 *
 * @return OE_OK on success
 */
OE_Result OE_Random(void* data, size_t size);

OE_EXTERNC_END

#endif /* _OE_RANDOM_H */
