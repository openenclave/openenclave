// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file result.h
 *
 * This file defines Open Enclave return codes (results).
 *
 */
#ifndef _OE_INTERNAL_RESULT_H
#define _OE_INTERNAL_RESULT_H

#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/* Return true if the result parameter matches an oe_result_t enum tag. */
bool oe_is_valid_result(uint32_t result);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_RESULT_H */
