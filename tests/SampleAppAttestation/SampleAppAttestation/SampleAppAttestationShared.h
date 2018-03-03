// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>

typedef struct _CREATE_APP_ENCLAVE_REPORT_ARGS
{
    OE_Result Result;
    void* Report;
    uint32_t ReportSize;
} CREATE_APP_ENCLAVE_REPORT_ARGS;
