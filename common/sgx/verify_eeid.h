// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_VERIFY_EEID_H
#define _OE_VERIFY_EEID_H

#include <openenclave/bits/report.h>
#include <openenclave/bits/types.h>

oe_result_t verify_eeid(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report,
    const oe_eeid_t* eeid);

#endif /* _OE_VERIFY_EEID_H */
