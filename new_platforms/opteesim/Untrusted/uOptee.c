/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <windows.h>
#include <stdint.h>
#include <openenclave/host.h>
#include <OpteeCalls.h>
#include <stdio.h>
#include <assert.h>
#include <TrEEGenService.h>
#include "tee_api.h"

#define ARRAY_SIZE(x)  (sizeof(x) / sizeof(*(x)))
#define TA_PREFIX L"\\\\.\\WindowsTrustedRT\\"

#define MOCK_RPC_KEY 0x12345678

typedef TEE_Result (*OpenTASessionProc)(
    const TEE_UUID *destination,
    uint32_t cancellationRequestTimeout,
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS],
    TEE_TASessionHandle *session,
    uint32_t *returnOrigin);

typedef TEE_Result (*InvokeTACommandProc)(
    TEE_TASessionHandle session,
    uint32_t cancellationRequestTimeout,
    uint32_t commandID, uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS],
    uint32_t *returnOrigin);

typedef TEE_Result (*InvokeREECallbackProc)(
    uint32_t commandID,
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS]);

typedef void (*SetREECallbackProc)(
    InvokeREECallbackProc reeCallbackProc);

typedef struct {
    LIST_ENTRY Link;
    HMODULE hModule;
    TEE_TASessionHandle hSession;
    OpenTASessionProc OpenTASession;
    InvokeTACommandProc InvokeTACommand;
} TASession;

LIST_ENTRY g_TASessions = { &g_TASessions, &g_TASessions };

OpteeRpcCallbackType g_RpcCallback = NULL;
void* g_RpcCallbackContext = NULL;

TEE_Result InvokeREECallback(
    uint32_t commandID,
    uint32_t paramTypes,
    TEE_Param params[TEE_NUM_PARAMS]) 
{
    uint32_t rpcType = params[0].value.a;
    uint32_t rpcKey = params[0].value.b;
    assert(rpcKey == MOCK_RPC_KEY);
    const uint8_t* in_buffer = (const uint8_t*)params[1].memref.buffer;
    uint32_t in_buffer_size = params[1].memref.size;
    uint8_t* out_buffer = (uint8_t*)params[2].memref.buffer;
    uint32_t out_buffer_size = params[2].memref.size;

    uint32_t sizeWritten;
    BOOL ok = g_RpcCallback(g_RpcCallbackContext, rpcType, in_buffer, in_buffer_size, out_buffer, out_buffer_size, &sizeWritten);

    params[2].memref.size = sizeWritten;
    return (ok && sizeWritten <= out_buffer_size) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

HANDLE __stdcall Tcps_CreateFileW(
    const WCHAR*          lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile)
{
    if (wcsncmp(lpFileName, TA_PREFIX, wcslen(TA_PREFIX)) == 0) {
#ifndef _DEBUG
        // We currently comment this out since creating the regkey requires admin
        // which means it can't be run on the build server.

        // First verify that the regkey exists.
        WCHAR keyPath[256];
        HKEY hKey;
        swprintf_s(keyPath, ARRAY_SIZE(keyPath), L"SYSTEM\\CurrentControlSet\\Services\\OpteeTree\\Parameters\\SecureServices\\%ls", 
            lpFileName + wcslen(TA_PREFIX));
        if (RegOpenKey(HKEY_LOCAL_MACHINE, keyPath, &hKey) != 0) {
            return INVALID_HANDLE_VALUE;
        }
        RegCloseKey(hKey);
#endif

        // Copy the GUID except the surrounding {}.
        WCHAR uuidString[256];
        wcscpy_s(uuidString, ARRAY_SIZE(uuidString), lpFileName + wcslen(TA_PREFIX) + 1);
        uuidString[wcslen(uuidString) - 1] = 0;

        WCHAR fileName[256];
        swprintf_s(fileName, ARRAY_SIZE(fileName), L"%ls.dll", uuidString);
        HMODULE hModule = LoadLibraryW(fileName);
        if (hModule == NULL) {
            return INVALID_HANDLE_VALUE;
        }

        OpenTASessionProc TEE_OpenTASession = (OpenTASessionProc)GetProcAddress(hModule, "TEE_OpenTASession_Export");
        if (TEE_OpenTASession == NULL) {
            FreeLibrary(hModule);
            return INVALID_HANDLE_VALUE;
        }

        SetREECallbackProc TEE_SetREECallbackProc = (SetREECallbackProc)GetProcAddress(hModule, "TEE_SetREECallback");
        if (TEE_SetREECallbackProc == NULL) {
            FreeLibrary(hModule);
            return INVALID_HANDLE_VALUE;
        }
        TEE_SetREECallbackProc(InvokeREECallback);

        InvokeTACommandProc TEE_InvokeTACommand = (InvokeTACommandProc)GetProcAddress(hModule, "TEE_InvokeTACommand_Export");
        if (TEE_InvokeTACommand == NULL) {
            FreeLibrary(hModule);
            return INVALID_HANDLE_VALUE;
        }

        TEE_TASessionHandle sessionHandle = NULL;
        TEE_Result result = TEE_OpenTASession(NULL, 0, 0, NULL, &sessionHandle, NULL);
        if (result != TEE_SUCCESS) {
            FreeLibrary(hModule);
            return INVALID_HANDLE_VALUE;
        }

        TASession* session = (TASession*)malloc(sizeof(*session));
        if (session == NULL) {
            FreeLibrary(hModule);
            return INVALID_HANDLE_VALUE;
        }

        // Insert in sessions list.
        session->Link.Blink = &g_TASessions;
        g_TASessions.Flink->Blink = &session->Link;
        session->Link.Flink = g_TASessions.Flink;
        g_TASessions.Flink = &session->Link;

        session->hModule = hModule;
        session->hSession = sessionHandle;
        session->OpenTASession = TEE_OpenTASession;
        session->InvokeTACommand = TEE_InvokeTACommand;
        return session;
    }
    return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

#undef CloseHandle
int __stdcall Tcps_CloseHandle(
    _In_ void* hObject)
{
    // See if object is in sessions list.
    LIST_ENTRY* le;
    for (le = g_TASessions.Flink; le != &g_TASessions; le = le->Flink) {
        if (le == hObject) {
            // Remove from sessions list.
            le->Blink->Flink = le->Flink;
            le->Flink->Blink = le->Blink;

            TASession* session = (TASession*)hObject;
            FreeLibrary(session->hModule);
            free(session);
            return 0;
        }
    }

    return CloseHandle(hObject);
}

_Use_decl_annotations_
BOOL
OPTEE_CALL
CallOpteeCommand(
    HANDLE                  TreeServiceHandle,
    uint32_t                FunctionCode,
    void *                  CommandInputBuffer,
    uint32_t                CommandInputSize,
    void *                  CommandOutputBuffer,
    uint32_t                CommandOutputSize,
    uint32_t *              CommandOutputSizeWritten,
    OpteeRpcCallbackType    RpcCallback,
    void *                  RpcCallbackContext)
{
    assert(TreeServiceHandle != INVALID_HANDLE_VALUE);

    TASession* session = (TASession*)TreeServiceHandle;
    TEE_Param params[4] = { 0 };
    ULONG outputSizeRounded;
    ULONG inputSizeRounded;
    uint8_t *inputHeader = NULL, *outputHeader = NULL;
    uint32_t requestKey = GetCurrentThreadId();

    *CommandOutputSizeWritten = 0;

    g_RpcCallback = RpcCallback;
    g_RpcCallbackContext = RpcCallbackContext;

    // Add header to input buffer, and make sure the input buffer is large enough
    // to fit the largest RPC output data.
    assert((CommandInputBuffer != NULL) || (CommandInputSize == 0));
    inputSizeRounded = max(
        sizeof(GENSVC_INPUT_BUFFER_HEADER) + CommandInputSize,
        OPTEE_MINIMUM_COMMAND_INPUT_SIZE);

    inputHeader = malloc(inputSizeRounded);
    assert(inputHeader != NULL);
    memcpy(((PGENSVC_INPUT_BUFFER_HEADER)inputHeader) + 1, CommandInputBuffer, CommandInputSize);

    ((PGENSVC_INPUT_BUFFER_HEADER)inputHeader)->Type = GenSvcInputTypeCommand;
    ((PGENSVC_INPUT_BUFFER_HEADER)inputHeader)->Key = requestKey;
    ((PGENSVC_INPUT_BUFFER_HEADER)inputHeader)->InputDataSize = CommandInputSize;
    ((PGENSVC_INPUT_BUFFER_HEADER)inputHeader)->OutputDataSize = CommandOutputSize;

    // Add header to output buffer, and make sure the input buffer is large enough
    // to fit the largest RPC input data.
    assert((CommandOutputBuffer != NULL) || (CommandOutputSize == 0));
    outputSizeRounded = max(
        sizeof(GENSVC_OUTPUT_BUFFER_HEADER) + CommandOutputSize,
        OPTEE_MINIMUM_COMMAND_OUTPUT_SIZE);

    outputHeader = malloc(outputSizeRounded);
    assert(outputHeader != NULL);

    params[0].value.a = MOCK_RPC_KEY;
    params[1].memref.buffer = CommandInputBuffer;
    params[1].memref.size = CommandInputSize;
    params[2].memref.buffer = CommandOutputBuffer;
    params[2].memref.size = CommandOutputSize;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_NONE);

    TEE_Result result = session->InvokeTACommand(session->hSession, 0, FunctionCode, exp_param_types, params, NULL);

    *CommandOutputSizeWritten = params[2].memref.size;

    if (inputHeader != NULL)
    {
        free(inputHeader);
    }

    if (outputHeader != NULL)
    {
        free(outputHeader);
    }

    return (result == TEE_SUCCESS);
}
