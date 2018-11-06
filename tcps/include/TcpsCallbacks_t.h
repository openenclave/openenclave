/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error TcpsCallbacks_t.h should only be included with TRUSTED_CODE
#endif
#include "oeenclave.h"

#define INVALID_SECURE_CALLBACK_ID (-1)

/* Helper layer defines. */
typedef void* (*PfnCallback)(void);

typedef int ocall_callback_id;

typedef struct _Tcps_SecureCallbackContext {
    ocall_callback_id CallbackFnId;
    PfnCallback CallbackFn;
    void* Context;
    void* Connection;
} Tcps_SecureCallbackContext;

int GetSecureCallbackId(
	ocall_callback_id a_CallbackFnId,
	PfnCallback a_pfnCallback,
	void* a_Connection,
	void* a_Context);

Tcps_SecureCallbackContext* GetSecureCallbackContextById(int a_CallbackId);
void FreeSecureCallbackContext(int a_CallbackId);

void FreeSecureCallbackContextsByConnection(void* a_Connection);
