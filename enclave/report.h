// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_REPORT_H
#define _OE_ENCLAVE_REPORT_H

#include <openenclave/bits/sgxtypes.h>
#include <openenclave/types.h>

OE_Result SGX_CreateReport(
    const SGX_TargetInfo* targetInfo,
    const SGX_ReportData* reportData,
    SGX_Report* report);

OE_Result _HandleGetSGXReport(uint64_t argIn);

#endif /* _OE_ENCLAVE_REPORT_H */
