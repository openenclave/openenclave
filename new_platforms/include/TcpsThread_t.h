/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif

oe_result_t
TcpsCreateThread(
    _Out_ HANDLE* threadHandle,
    _In_ int contextId);
