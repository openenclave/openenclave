// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_OE_COLLATERALS_H
#define _OE_COMMON_OE_COLLATERALS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/**
 * Get the collaterals for the respective remote report.
 *
 * @param[in] remote_report The remote report.
 * @param[in] remote_report_size The size of the remote report.
 * @param[out] collaterals_buffer The buffer where to store the collaterals.
 * @param[out] collaterals_buffer_size The size of the collaterals.
 */
oe_result_t oe_get_collaterals_internal(
    const uint8_t* remote_report,
    size_t remote_report_size,
    uint8_t** collaterals_buffer,
    size_t* collaterals_buffer_size);

/**
 * Free up any resources allocated by oe_get_collateras()
 *
 * @param[in] collaterals_buffer The buffer containing the collaterals.
 */
void oe_free_collaterals_internal(uint8_t* collaterals_buffer);

OE_EXTERNC_END

#endif /* _OE_COMMON_OE_COLLATERALS_H */
