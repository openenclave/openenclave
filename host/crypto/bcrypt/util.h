// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_UTIL_H
#define _OE_HOST_CRYPTO_UTIL_H

#include <openenclave/internal/datetime.h>
#include <openenclave/internal/result.h>

#include <windows.h>

/**
 * Convert FILETIME to oe_datetime_t.
 *
 * @param filetime[in] The FILETIME to convert.
 * @param datetime[out] The corresponding oe_datetime_t.
 */
oe_result_t oe_util_filetime_to_oe_datetime(
    const FILETIME* filetime,
    oe_datetime_t* datetime);

#endif /* _OE_HOST_CRYPTO_UTIL_H */
