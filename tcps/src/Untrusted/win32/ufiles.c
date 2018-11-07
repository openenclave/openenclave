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
#include "../oeoverintelsgx_u.h"

oe_result_t
ocall_ExportPublicCertificate(
    oe_buffer256 certificateFileNameExported,
    oe_buffer4096 ptr,
    size_t len)
{
    Tcps_Trace(Tcps_TraceLevelDebug, "ocall_ExportPublicCertificate: export to (%s)\n", certificateFileNameExported);

    return ocall_ExportFile(certificateFileNameExported, Tcps_False, ptr, len);
}

static
oe_result_t
internal_FindFirstUntrustedFile(
    oe_buffer256 filePathWithWildcards,
    char* matchingFileName,
    uint32_t matchingFileNameSize,
    uint32_t *findNextHandle)
{
    WIN32_FIND_DATA findData;
    size_t fileNameLength;
    size_t characterIndex;
    HANDLE findHandle = INVALID_HANDLE_VALUE;
    char pathWindowsFormat[MAX_PATH];

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_FindFirstUntrustedFile");

    Tcps_GotoErrorIfTrue(matchingFileNameSize == 0, OE_INVALID_PARAMETER);
    matchingFileName[0] = '\0';

    /* Make a copy of the input path, and change '/' separators to '\\' */
    fileNameLength = strlen(filePathWithWildcards.buffer);
    Tcps_GotoErrorIfTrue(fileNameLength >= sizeof(pathWindowsFormat), OE_FAILURE);
    memcpy(pathWindowsFormat, filePathWithWildcards.buffer, fileNameLength + 1);

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
    *findNextHandle = (uint32_t)findHandle;
   
Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    *findNextHandle = (uint32_t)INVALID_HANDLE_VALUE;

    if (findHandle != INVALID_HANDLE_VALUE)
    {
        TCPS_VERIFY(FindClose(findHandle));
    }
Tcps_FinishErrorHandling;
}

FindFirstUntrustedFile_Result
ocall_FindFirstUntrustedFile(
    oe_buffer256 filePathWithWildcards,
    uint32_t matchingFileNameSize)
{
    FindFirstUntrustedFile_Result result;

    result.status = internal_FindFirstUntrustedFile(
        filePathWithWildcards,
        result.matchingFileName,
        matchingFileNameSize,
        &result.findNextHandle);

    return result;
}

static
oe_result_t
internal_FindNextUntrustedFile(
    uint32_t findNextHandle,
    char* matchingFileName,
    uint32_t matchingFileNameSize)
{
    BOOL found;
    WIN32_FIND_DATA findData;
    size_t fileNameLength;
    HANDLE findHandle = (HANDLE)findNextHandle;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_FindNextUntrustedFile");

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

FindNextUntrustedFile_Result
ocall_FindNextUntrustedFile(
    uint32_t findNextHandle,
    uint32_t matchingFileNameSize)
{
    FindNextUntrustedFile_Result result;
    result.result = internal_FindNextUntrustedFile(findNextHandle, result.matchingFileName, matchingFileNameSize);
    return result;
}

oe_result_t
ocall_FindNextUntrustedFileClose(
    uint32_t findNextHandle)
{
    BOOL success;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_FindNextUntrustedFileClose");

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
