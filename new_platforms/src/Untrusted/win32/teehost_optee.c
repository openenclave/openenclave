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
#include <openenclave/host.h>

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

oe_result_t oe_create_enclave_helper(
    _In_z_ const char* a_TaIdString,
    uint32_t a_Flags,
    _Out_ oe_enclave_t** a_pId)
{
    char uuidstring[80];
    strcpy_s(uuidstring, sizeof(uuidstring), a_TaIdString);

    /* Remove ".ta" extension, if one is present. */
    size_t len = strlen(uuidstring);
    if ((len > 3) && (strcmp(&uuidstring[len - 3], ".ta") == 0)) {
        uuidstring[len - 3] = 0;
    }

    *a_pId = NULL;

    OE_UNUSED(a_Flags);

    /* Convert string to GUID. */
    UUID uuid;
    HRESULT hr = UuidFromString((RPC_CSTR)uuidstring, &uuid);
    if (hr != S_OK) {
        return OE_FAILURE;
    }

    /* Open a session to the TA. */
    HANDLE hService = OpenServiceHandleByFilename(&uuid);
    *a_pId = (oe_enclave_t*)hService;
    if (hService == INVALID_HANDLE_VALUE) {
        return OE_FAILURE;
    }
    assert(*a_pId != NULL);

    /* Proactively initialize sockets so the enclave isn't required to. */
    WSADATA wsaData;
    (void)WSAStartup(0x202, &wsaData);

    return OE_OK;
}

oe_result_t oe_terminate_enclave(_In_ oe_enclave_t* enclave)
{
    WSACleanup();

    if (enclave != NULL) {
        CloseHandle((HANDLE)enclave);
    }
    return OE_OK;
}
