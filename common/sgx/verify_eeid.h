// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_VERIFY_EEID_H
#define _OE_VERIFY_EEID_H

#include <openenclave/bits/eeid.h>

oe_result_t verify_eeid(oe_report_t* report, const oe_eeid_t* eeid);

oe_result_t verify_eeid_nr(
    const uint8_t* r_mrenclave,
    const uint8_t* r_mrsigner,
    uint16_t r_product_id,
    uint32_t r_security_version,
    uint64_t r_attributes,
    const oe_eeid_t* eeid);

#endif /* _OE_VERIFY_EEID_H */
