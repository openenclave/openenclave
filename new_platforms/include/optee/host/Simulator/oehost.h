/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_HOST_H
# error include <openenclave/host.h> instead of including oehost.h directly
#endif

#include "..\..\..\oehost.h"

/* We need to redefine CreaateFileW in order to simulate calls to it to
 * launch a TA in OP-TEE.
 */
#include <windows.h>
#define CreateFileW Tcps_CreateFileW
#define CloseHandle Tcps_CloseHandle

void* _stdcall Tcps_CreateFileW(
  _In_z_ const wchar_t* lpFileName,
  _In_ unsigned long    dwDesiredAccess,
  _In_ unsigned long    dwShareMode,
  _In_opt_ void*        lpSecurityAttributes,
  _In_ unsigned long    dwCreationDisposition,
  _In_ unsigned long    dwFlagsAndAttributes,
  _In_opt_ void*        hTemplateFile);

int __stdcall Tcps_CloseHandle(
  _In_ void* hObject);

#define _APISETHANDLE_
