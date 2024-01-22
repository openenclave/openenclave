// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TDX_QUOTE_H
#define _OE_COMMON_TDX_QUOTE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/datetime.h>

OE_EXTERNC_BEGIN

/*!
 * Verify TDX quote with endorsements.
 *
 * @param[in] quote Input quote.
 * @param[in] quote_size The size of the quote.
 * @param[in] endorsements Input endorsements.
 * @param[in] endorsements_size The size of endorsements.
 * @param[in] input_validation_time Optional time to use for validation,
 * defaults to the time the endorsements were created if null. Note that
 * if the input time is after than the endorsement creation time, then the
 * CRLs might have updated in the period between the input time and the
 * endorsement creation time.
 * @param[out] verification_result Optional pointer to the verification
 * result.
 * @param[out] supplemental_data Optional pointer to the supplemental data.
 * @param[out] supplemental_data_size @optional pointer to the size of
 * supplemental data.
 *
 */
oe_result_t oe_verify_quote_with_tdx_endorsements(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* input_validation_time,
    uint32_t* verification_result,
    uint8_t** supplemental_data,
    size_t* supplemental_data_size);

OE_EXTERNC_END

#endif // _OE_COMMON_TDX_QUOTE_H
