/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error TcpsThread_t.h should only be included with TRUSTED_CODE
#endif
#include "tcps_t.h"

Tcps_StatusCode
TcpsCreateThread(
    _Out_ HANDLE* threadHandle,
    _In_ int contextId);
