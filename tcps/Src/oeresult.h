/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define V2_FUNCTION_ID_OFFSET 0x10000

oe_result_t GetOEResultFromSgxStatus(sgx_status_t status);
sgx_status_t GetSgxStatusFromOEResult(oe_result_t result);
