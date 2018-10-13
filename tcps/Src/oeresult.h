/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

oe_result_t GetOEResultFromSgxStatus(sgx_status_t status);
sgx_status_t GetSgxStatusFromOEResult(oe_result_t result);
