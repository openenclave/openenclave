/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <initguid.h>
#include <string.h>
#include <strsafe.h>
#include <rpc.h>
#include "tcps_u.h"
#include "TcpsCalls_u.h"

static HANDLE OpenServiceHandleByFilename(_In_ LPCGUID ServiceGuid)
{
    WCHAR interfaceGuid[1024];
    WCHAR interfaceSymlink[1024];
    HANDLE serviceHandle;

    serviceHandle = INVALID_HANDLE_VALUE;
    swprintf_s(
        interfaceGuid,
        _countof(interfaceGuid),
        L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        ServiceGuid->Data1,
        ServiceGuid->Data2,
        ServiceGuid->Data3,
        ServiceGuid->Data4[0],
        ServiceGuid->Data4[1],
        ServiceGuid->Data4[2],
        ServiceGuid->Data4[3],
        ServiceGuid->Data4[4],
        ServiceGuid->Data4[5],
        ServiceGuid->Data4[6],
        ServiceGuid->Data4[7]);

    swprintf_s(interfaceSymlink, _countof(interfaceSymlink),
               L"\\\\.\\WindowsTrustedRT\\%ws", interfaceGuid);

    serviceHandle = CreateFileW(
        interfaceSymlink,
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

#if 0
    if (serviceHandle == INVALID_HANDLE_VALUE) {
        wprintf(
            L"Error: Opening service: Guid=%ws, Symlink=%ws failed, "
               L"status %d!\n",
            interfaceGuid,
            interfaceSymlink,
            GetLastError());

    } else {
        wprintf(
            L"Opening service: Guid=%ws succeeded, "
            L"service handle %p!\n",
            interfaceGuid,
            serviceHandle);

    }
#endif

    return serviceHandle;
}

Tcps_StatusCode Tcps_CreateTA(
    _In_z_ const char* a_TaIdString,
    _In_ uint32_t a_Flags,
    _Out_ sgx_enclave_id_t* a_pId)
{
    *a_pId = (sgx_enclave_id_t)INVALID_HANDLE_VALUE;

    TCPS_UNUSED(a_Flags);

    /* Convert string to GUID. */
    UUID uuid;
    HRESULT hr = UuidFromString((RPC_CSTR)a_TaIdString, &uuid);
    if (hr != S_OK) {
        return Tcps_Bad;
    }

    /* Open a session to the TA. */
    HANDLE hService = OpenServiceHandleByFilename(&uuid);
    *a_pId = (sgx_enclave_id_t)hService;
    if (hService == INVALID_HANDLE_VALUE) {
        return Tcps_Bad;
    }
    TCPS_ASSERT(*a_pId != (sgx_enclave_id_t)-1);

    /* Proactively initialize sockets so the enclave isn't required to. */
    WSADATA wsaData;
    (void)WSAStartup(0x202, &wsaData);

    return Tcps_Good;
}

Tcps_StatusCode Tcps_DestroyTA(
    _In_ sgx_enclave_id_t a_Id)
{
    WSACleanup();

    if (a_Id != (sgx_enclave_id_t)INVALID_HANDLE_VALUE) {
        CloseHandle((HANDLE)a_Id);
        a_Id = (sgx_enclave_id_t)INVALID_HANDLE_VALUE;
    }
    return Tcps_Good;
}
