/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error TCPS-SDK\Inc\optee\Trusted headers should only be included with TRUSTED_CODE
#endif

/* Generated code includes a file with this name.  One exists in the Intel
 * SGX SDK's tlibc include directory, but when building for OP-TEE, we use
 * OP-TEE's libc instead of Intel's, and OP-TEE's has no file of this name.
 * Hence this file allows the generated code to build without hitting a
 * missing file error.
 */
