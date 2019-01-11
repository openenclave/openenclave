/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <direct.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <assert.h>

#include <openenclave/host.h>
#include "stdio_u.h"

oe_result_t
ocall_ExportPublicCertificate(
    const char* certificateFileNameExported,
    const void* ptr,
    size_t len)
{
    Tcps_Trace(Tcps_TraceLevelDebug, "ocall_ExportPublicCertificate: export to (%s)\n", certificateFileNameExported);

    return ocall_ExportFile(certificateFileNameExported, Tcps_False, ptr, len);
}

static
oe_result_t
internal_opendir(
    const char* filePathWithWildcards,
    char* matchingFileName,
    uint32_t matchingFileNameSize,
    uintptr_t *findNextHandle)
{
    WIN32_FIND_DATA findData;
    size_t fileNameLength;
    size_t characterIndex;
    HANDLE findHandle = INVALID_HANDLE_VALUE;
    char pathWindowsFormat[MAX_PATH];

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_opendir");

    Tcps_GotoErrorIfTrue(matchingFileNameSize == 0, OE_INVALID_PARAMETER);
    matchingFileName[0] = '\0';

    /* Make a copy of the input path, and change '/' separators to '\\' */
    fileNameLength = strlen(filePathWithWildcards);
    Tcps_GotoErrorIfTrue(fileNameLength >= sizeof(pathWindowsFormat), OE_FAILURE);
    memcpy(pathWindowsFormat, filePathWithWildcards, fileNameLength + 1);

    for (characterIndex = 0; characterIndex < fileNameLength; characterIndex++)
    {
        if (pathWindowsFormat[characterIndex] == '/')
        {
            pathWindowsFormat[characterIndex] = '\\';
        }
    }

    /* Find first file. */
    findHandle = FindFirstFile(pathWindowsFormat, &findData);
    Tcps_GotoErrorIfTrue(findHandle == INVALID_HANDLE_VALUE, OE_NOT_FOUND);

    fileNameLength = strlen(findData.cFileName);
    Tcps_GotoErrorIfTrue(fileNameLength >= matchingFileNameSize, OE_FAILURE);

    /* Return the first file path. */
    memcpy(matchingFileName, findData.cFileName, fileNameLength + 1);
    *findNextHandle = (uintptr_t)findHandle;
   
Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    *findNextHandle = (uintptr_t)INVALID_HANDLE_VALUE;

    if (findHandle != INVALID_HANDLE_VALUE)
    {
        TCPS_VERIFY(FindClose(findHandle));
    }
Tcps_FinishErrorHandling;
}

FindFirstUntrustedFile_Result
ocall_opendir(
    const char* filePathWithWildcards,
    uint32_t matchingFileNameSize)
{
    FindFirstUntrustedFile_Result result;

    result.status = internal_opendir(
        filePathWithWildcards,
        result.d_name,
        matchingFileNameSize,
        &result.findNextHandle);

    return result;
}

static
oe_result_t
internal_readdir(
    uintptr_t findNextHandle,
    char* matchingFileName,
    uint32_t matchingFileNameSize)
{
    BOOL found;
    WIN32_FIND_DATA findData;
    size_t fileNameLength;
    HANDLE findHandle = (HANDLE)findNextHandle;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_readdir");

    Tcps_GotoErrorIfTrue(matchingFileNameSize == 0, OE_INVALID_PARAMETER);
    matchingFileName[0] = '\0';

    if (findHandle == INVALID_HANDLE_VALUE)
    {
        assert(FALSE);
        Tcps_GotoErrorWithStatus(OE_INVALID_PARAMETER);
    }

    found = FindNextFile(findHandle, &findData);
    Tcps_GotoErrorIfTrue(!found, OE_NOT_FOUND);

    fileNameLength = strlen(findData.cFileName);
    Tcps_GotoErrorIfTrue(fileNameLength >= matchingFileNameSize, OE_FAILURE);

    memcpy(matchingFileName, findData.cFileName, fileNameLength + 1);
   
Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

ocall_struct_dirent
ocall_readdir(
    uintptr_t findNextHandle,
    uint32_t matchingFileNameSize)
{
    ocall_struct_dirent result;
    result.status = internal_readdir(findNextHandle, result.d_name, matchingFileNameSize);
    return result;
}

oe_result_t
ocall_closedir(
    uintptr_t findNextHandle)
{
    BOOL success;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_closedir");

    assert((HANDLE)findNextHandle != INVALID_HANDLE_VALUE);
  
    success = FindClose((HANDLE)findNextHandle);
   
    if (!success)
    {
        assert(FALSE);
        Tcps_GotoErrorWithStatus(OE_INVALID_PARAMETER);
    }
   
Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}
