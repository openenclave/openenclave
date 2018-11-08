/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

/* The <openenclave/edger8r/enclave.h> header includes <intrin.h> when
 * compiling x64 with Visual Studio.  However, when using the Intel SGX
 * SDK underneath, the Windows SDK headers are not included.  We thus
 * need this file to exist in order to compile for 64-bit.
 */
