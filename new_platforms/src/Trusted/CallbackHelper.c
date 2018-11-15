/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>

#include <TcpsCallbacks_t.h>

void ecall_Helper_dummy(void);

#define MAX_CALLBACK_CONTEXT 10
int g_CallbackContextCount = 0;
Tcps_SecureCallbackContext g_SecureCallbackContext[MAX_CALLBACK_CONTEXT] = {0};

#define ID_OFFSET 100

int GetSecureCallbackId(
    ocall_callback_id a_CallbackFnId,
    PfnCallback a_pfnCallback,
    void* a_Connection,
    void* a_Context)
{
    int i;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GetSecureCallbackId");

    // Tcps_Trace(Tcps_TraceLevelError, "GetSecureCallbackId: a_Connection = %p\n", a_Connection);

    // Look for an existing match.
    for (i = 0; i < MAX_CALLBACK_CONTEXT; i++) {
        if ((g_SecureCallbackContext[i].CallbackFnId == a_CallbackFnId) && 
            (g_SecureCallbackContext[i].CallbackFn == a_pfnCallback) &&
            (g_SecureCallbackContext[i].Context == a_Context) &&
            (g_SecureCallbackContext[i].Connection == a_Connection)) {
            // Tcps_Trace(Tcps_TraceLevelError, "GetSecureCallbackId: returning callback ID %d - already existing\n", i + ID_OFFSET);
            return i + ID_OFFSET;
        }
    }

    // Allocate a new context.
    for (i = 0; i < MAX_CALLBACK_CONTEXT; i++) {
        if ((g_SecureCallbackContext[i].CallbackFnId == 0) &&
            (g_SecureCallbackContext[i].CallbackFn == NULL) &&
            (g_SecureCallbackContext[i].Context == NULL) &&
            (g_SecureCallbackContext[i].Connection == NULL)) {
            g_SecureCallbackContext[i].CallbackFnId = a_CallbackFnId;
            g_SecureCallbackContext[i].CallbackFn = a_pfnCallback;
            g_SecureCallbackContext[i].Context = a_Context;
            g_SecureCallbackContext[i].Connection = a_Connection;
            // Tcps_Trace(Tcps_TraceLevelError, "GetSecureCallbackId: returning callback ID %d - new\n", i + ID_OFFSET);
            return i + ID_OFFSET;
        }
    }

    Tcps_GotoErrorWithStatus(OE_FAILURE);

Tcps_BeginErrorHandling;
    oe_assert(0);
    return -1;
Tcps_FinishErrorHandling;
}

Tcps_SecureCallbackContext* GetSecureCallbackContextById(int a_CallbackId)
{
    int i = a_CallbackId - ID_OFFSET;
    if ((i < 0) || (i >= MAX_CALLBACK_CONTEXT)) {
        return NULL;
    }
    return &g_SecureCallbackContext[i];
}

void FreeSecureCallbackContext(int a_CallbackId)
{
    // Tcps_Trace(Tcps_TraceLevelError, "FreeSecureCallbackContext: freeing callback ID %d\n", a_CallbackId);

    int i = a_CallbackId - ID_OFFSET;

    oe_assert(i >= 0);
    oe_assert(i < MAX_CALLBACK_CONTEXT);

    g_SecureCallbackContext[i].CallbackFnId = 0;
    g_SecureCallbackContext[i].CallbackFn = NULL;
    g_SecureCallbackContext[i].Context = NULL;
    g_SecureCallbackContext[i].Connection = NULL;
}

void FreeSecureCallbackContextsByConnection(void* a_Connection)
{
    int i;

    // Tcps_Trace(Tcps_TraceLevelError, "FreeSecureCallbackContextsByConnection: a_Connection = %p\n", a_Connection);

    for (i = 0; i < MAX_CALLBACK_CONTEXT; i++) {
        if (g_SecureCallbackContext[i].Connection == a_Connection) {
            // Tcps_Trace(Tcps_TraceLevelError, "FreeSecureCallbackContextsByConnection: freeing callback ID %d\n", i + ID_OFFSET);

            g_SecureCallbackContext[i].CallbackFnId = 0;
            g_SecureCallbackContext[i].CallbackFn = NULL;
            g_SecureCallbackContext[i].Context = NULL;
            g_SecureCallbackContext[i].Connection = NULL;
        }
    }
}

/* Dummy ecall to keep compiler happy. */
void
ecall_Helper_dummy(void)
{
}
