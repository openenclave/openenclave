// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
 * Need to define WIN32_NO_STATUS before including Windows, because some macros
 * are defined in both Windows.h and ntstatus.h. The WIN32_NO_STATUS will
 * prevent these redefinitions.
 */
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>
#include <wincrypt.h>
