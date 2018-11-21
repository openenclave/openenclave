/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef OE_USE_OPTEE
# error sgxoveroptee.h should only be included with OE_USE_OPTEE
#endif

#include <sgx_error.h>

/* The sgx_error.h in the Intel SGX SDK for Linux is missing the following value
 * that appears in the Intel SGX SDK for Windows.
 */
#define SGX_ERROR_FEATURE_NOT_SUPPORTED SGX_MK_ERROR(0x0008)
