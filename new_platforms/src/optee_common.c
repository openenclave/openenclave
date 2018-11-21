/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>

#ifndef _In_
#include "sal_unsup.h"
#endif

oe_result_t oe_parse_report(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_ oe_report_t* parsed_report)
{
    /* Not yet supported */
    return OE_UNSUPPORTED;
}

oe_result_t oe_get_target_info_v2(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Outptr_ void** target_info_buffer,
    _Out_ size_t* target_info_size)
{
    /* Not yet supported */
    return OE_UNSUPPORTED;
}

oe_result_t oe_get_target_info_v1(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_writes_bytes_(*target_info_size) void* target_info_buffer,
    _Inout_ size_t* target_info_size)
{
    return OE_UNSUPPORTED;
}

void oe_free_target_info(_In_ void* target_info_buffer)
{
    return;
}
