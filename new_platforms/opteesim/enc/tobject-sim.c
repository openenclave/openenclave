/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdio.h>
#include <windows.h>
#include <assert.h>
#include <tee_api.h>

static const char* TEEP_ObjectIDToString(
    _In_reads_bytes_(objectIDLen) void* objectID,
    _In_ size_t objectIDLen)
{
    size_t bufsz = sizeof(char) * ((objectIDLen * 2) + 1);
    char* output = malloc(bufsz);
    if (output == NULL) {
        return NULL;
	}

	char* ptr = &output[0];
    for (size_t i = 0; i < objectIDLen; i++) {
        ptr += sprintf_s(ptr, bufsz, "%02X", ((const unsigned char *)objectID)[i]);
    }

    return output;
}

TEE_Result TEE_OpenPersistentObject(
    _In_ uint32_t storageID,
    _In_reads_bytes_(objectIDLen) void* objectID,
    _In_ size_t objectIDLen,
    _In_ uint32_t flags,
    _Out_ TEE_ObjectHandle* object)
{
    *object = (TEE_ObjectHandle)INVALID_HANDLE_VALUE;

	/* Note that objectID is a meaningless byte array (i.e. not necessarily a
     * string). */
    const char* fileName = TEEP_ObjectIDToString(objectID, objectIDLen);
    if (fileName == NULL || strlen(fileName) > MAX_PATH) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    DWORD dwFlags = 0;
    DWORD dwSharing = 0;

    if (flags & TEE_DATA_FLAG_ACCESS_READ) {
        dwFlags |= GENERIC_READ;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE_META) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_SHARE_READ) {
        dwSharing |= FILE_SHARE_READ;
    }
    if (flags & TEE_DATA_FLAG_SHARE_WRITE) {
        dwSharing |= FILE_SHARE_WRITE;
    }

    HANDLE hFile = CreateFileA(
        fileName,
        dwFlags,
        dwSharing,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    *object = (TEE_ObjectHandle)hFile;

    return (hFile == INVALID_HANDLE_VALUE) ? TEE_ERROR_ITEM_NOT_FOUND : TEE_SUCCESS;
}

TEE_Result TEE_CreatePersistentObject(
    _In_ uint32_t storageID,
    _In_reads_bytes_(objectIDLen) void* objectID,
    _In_ size_t objectIDLen,
    _In_ uint32_t flags,
    _In_ TEE_ObjectHandle attributes,
    _In_reads_bytes_(initialDataLen) void* initialData,
    _In_ size_t initialDataLen,
    _Out_ TEE_ObjectHandle* object)
{
    /* Support for InitialData is not implemented. */
    assert(initialData == NULL);
    assert(initialDataLen == 0);

    *object = (TEE_ObjectHandle)INVALID_HANDLE_VALUE;

	/* Note that objectID is a meaningless byte array (i.e. not necessarily a
     * string). */
    const char* fileName = TEEP_ObjectIDToString(objectID, objectIDLen);
    if (fileName == NULL || strlen(fileName) > MAX_PATH) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    DWORD dwFlags = 0;
    DWORD dwSharing = 0;
    DWORD dwCreationDisposition = (flags & TEE_DATA_FLAG_OVERWRITE) ? CREATE_ALWAYS : CREATE_NEW;

    if (flags & TEE_DATA_FLAG_ACCESS_READ) {
        dwFlags |= GENERIC_READ;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_ACCESS_WRITE_META) {
        dwFlags |= GENERIC_WRITE;
    }
    if (flags & TEE_DATA_FLAG_SHARE_READ) {
        dwSharing |= FILE_SHARE_READ;
    }
    if (flags & TEE_DATA_FLAG_SHARE_WRITE) {
        dwSharing |= FILE_SHARE_WRITE;
    }

    HANDLE hFile = CreateFileA(
        fileName,
        dwFlags,
        dwSharing,
        NULL,
        dwCreationDisposition,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    *object = (TEE_ObjectHandle)hFile;

    if (hFile != INVALID_HANDLE_VALUE) {
        return TEE_SUCCESS;
    }

    int err = GetLastError();
    return (err == ERROR_FILE_EXISTS) ? TEE_ERROR_ACCESS_CONFLICT : TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result TEE_SeekObjectData(
    _In_ TEE_ObjectHandle object,
    _In_ int32_t offset,
    _In_ TEE_Whence whence)
{
    HANDLE hFile = (HANDLE)object;
    DWORD result = SetFilePointer(hFile, offset, NULL, whence);
    return (result == INVALID_SET_FILE_POINTER) ? TEE_ERROR_STORAGE_NOT_AVAILABLE : TEE_SUCCESS;
}

TEE_Result TEE_ReadObjectData(
    _In_ TEE_ObjectHandle object,
    _Out_writes_bytes_to_(size, *count) void* buffer,
    _In_ size_t size,
    _Out_ uint32_t* count)
{
    HANDLE hFile = (HANDLE)object;
    BOOL ok = ReadFile(hFile, buffer, size, count, NULL);
    return (ok) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result TEE_WriteObjectData(
    _In_ TEE_ObjectHandle object,
    _In_reads_bytes_(size) void* buffer,
    _In_ size_t size)
{
    HANDLE hFile = (HANDLE)object;
    DWORD bytesWritten;
    BOOL ok = WriteFile(hFile, buffer, size, &bytesWritten, NULL);
    return (ok && bytesWritten == size) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result TEE_GetObjectInfo1(
    _In_ TEE_ObjectHandle object,
    _Out_ TEE_ObjectInfo* objectInfo)
{
    HANDLE hFile = (HANDLE)object;
    BY_HANDLE_FILE_INFORMATION info = { 0 };
    BOOL ok = GetFileInformationByHandle(hFile, &info);
    if (!ok) {
        return TEE_ERROR_GENERIC;
    }
    objectInfo->dataSize = info.nFileSizeLow;

    // We don't yet support the other fields.

    return TEE_SUCCESS;
}

void TEE_CloseObject(
    _In_ TEE_ObjectHandle object)
{
    HANDLE hFile = (HANDLE)object;
    CloseHandle(hFile);
}

TEE_Result TEE_CloseAndDeletePersistentObject1(
    _In_ TEE_ObjectHandle object)
{
    HANDLE hFile = (HANDLE)object;

    // Get the filename.
    char fileName[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleA(
        hFile,
        fileName,
        sizeof(fileName),
        FILE_NAME_NORMALIZED);
    CloseHandle(hFile);
    if (result == 0) {
        return TEE_ERROR_GENERIC;
    }

    // Delete the file.
    BOOL ok = DeleteFileA(fileName);
    return (ok) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}
