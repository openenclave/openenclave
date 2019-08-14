// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
 * Need to define WIN32_NO_STATUS before including Windows.h because some macros
 * are defined in both Windows.h and ntstatus.h. The WIN32_NO_STATUS will
 * prevent these redefinitions.
 *
 * Need to define NOCRYPT before including Windows.h to prevent it from pulling
 * in crypto headers before bcrypt.h, which we want to modify independently with
 * CERT_CHAIN_PARA_HAS_EXTRA_FIELDS to enable extended cert chain parameters.
 */
#define NOCRYPT
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#include <bcrypt.h>
#include <wincrypt.h>
