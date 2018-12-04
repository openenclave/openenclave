/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#define _NO_CRT_STDIO_INLINE
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include "tcps_string_t.h"
#include "stdio_t.h"
#include "enclavelibc.h"

#if defined(OE_USE_SGX)
#define DMSG printf
#define EMSG printf
#else
#include <trace.h>
#endif

void ecall_InitializeStdio() {}

int oe_fprintf(OE_FILE* const _Stream, char const* const _Format, ...)
{
    va_list _ArgList;
    va_start(_ArgList, _Format);

    return vfprintf(_Stream, _Format, _ArgList);
}

#ifdef OE_USE_SGX
int __cdecl __stdio_common_vfprintf(
    unsigned __int64 _Options,
    FILE*            _Stream,
    char const*      _Format,
    void*            _Locale,
    va_list          _ArgList)
{
    // Not implemented.
    return 0;
}
#endif

int oe_vfprintf(
    OE_FILE *stream,
    const char *format,  
    va_list argptr)
{
    int len;
    char* buffer;
    int written;

    len = _vsnprintf(NULL, 0, format, argptr);
    if (len < 0) {
        return -1;
    }

    buffer = oe_malloc(len + 1);
    if (buffer == NULL) {
        return -1;
    }
    len = _vsnprintf(buffer, len, format, argptr);
    written = fwrite(buffer, 1, len, stream);
    oe_free(buffer);

    return written;
}

HANDLE FindFirstFile(
    const char* lpFileName,
    WIN32_FIND_DATA* lpFindFileData)
{
    HANDLE handle;
    int result = FindFirstFileInternal(&handle, lpFileName, lpFindFileData);
    if (result != 0) {
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

/* Return non-zero on success, 0 on failure. */
int FindNextFile(HANDLE hFindFile, WIN32_FIND_DATA* findFileData)
{
    int err = FindNextFileInternal(hFindFile, findFileData);
    return (err == 0);
}

BOOL FindClose(HANDLE hFindFile)
{
    int result = FindCloseInternal(hFindFile);
    return result;
}

oe_result_t GetTrustedFileInBuffer(const char* trustedFilePath, char** pBuffer, size_t* pLen)
{
    int sizeRead;
    char* ptr;
    int64_t fileSize;
    oe_result_t tcpsStatus;
    OE_FILE* fp = NULL;

    *pBuffer = NULL;
    *pLen = 0;

    // Get the file size.
    tcpsStatus = GetTrustedFileSize(trustedFilePath, &fileSize);
    if (tcpsStatus != OE_OK) {
        return tcpsStatus;
    }
    if (fileSize <= 0) {
        EMSG("Trusted file %s is empty", trustedFilePath);
        return OE_FAILURE;
    }

    // Allocate the output buffer.
    ptr = oe_malloc((size_t)fileSize);
    if (ptr == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    // Read file into the buffer.
    fp = oe_fopen(OE_FILE_SECURE_BEST_EFFORT, trustedFilePath, "rb");
    if (fp == NULL) {
        extern errno_t errno;
        EMSG("fopen failed, errno = %u", errno);
        FreeTrustedFileBuffer(ptr);
        return OE_FAILURE;
    }
    sizeRead = oe_fread(ptr, 1, (size_t)fileSize, fp);
    oe_fclose(fp);
    if (sizeRead < fileSize) {
        // Truncated.
        EMSG("fileSize = %llu, sizeRead = %d", fileSize, sizeRead);
        FreeTrustedFileBuffer(ptr);
        return OE_FAILURE;
    }

    *pBuffer = ptr;
    *pLen = (size_t)fileSize; 
    return OE_OK;
}

void FreeTrustedFileBuffer(char* buffer)
{
    oe_free(buffer);
}

/* Returns TRUE if filename is in manifest, FALSE if not. */
static int IsInManifest(const char *manifestLocation, const char *filename)
{
    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA findFileData;
    int err = FindFirstFileInternal(&hFindFile, manifestLocation, &findFileData);
    int found = FALSE;
    while (err != ERROR_NO_MORE_FILES) {
        if (err != 0) {
            break;
        }
        if (strcmp(filename, findFileData.cFileName) == 0) {
            found = TRUE;
            break;
        }
        err = FindNextFileInternal(hFindFile, &findFileData);
    }
    FindCloseInternal(hFindFile);
    return found;
}

int AppendToManifest(const char* manifestLocation, const char* filename)
{
    WIN32_FIND_DATA findFileData;
    memset(&findFileData, 0, sizeof(findFileData));
    strcpy_s(findFileData.cFileName, sizeof(findFileData.cFileName), filename);

    if (IsInManifest(manifestLocation, filename)) {
        return 0;
    }

    return AppendToFile(manifestLocation, &findFileData, sizeof(findFileData));
}

/* Returns 0 on success, or non-zero on error. */
int AppendFilenameToManifest(const char* fullPathName)
{
    // Compose manifest filename.
    char manifest[256];
    const char* p = strrchr(fullPathName, '\\');
    const char *p2 = strrchr(fullPathName, '/');
    if ((p == NULL) && (p2 == NULL)) {
        oe_assert(FALSE);
        return 1;
    }
    if ((p == NULL) || (p < p2)) {
        p = p2;
    }
    p++;
    if (p - fullPathName >= (int)sizeof(manifest)) {
        return 1;
    }
    strncpy_s(manifest, sizeof(manifest), fullPathName, p - fullPathName);
    manifest[p - fullPathName] = 0;
    strcat_s(manifest, sizeof(manifest), "manifest");

    return AppendToManifest(manifest, p);
}

int ExportFile(const char* trustedLocation, const char* untrustedLocation)
{
    char* ptr;
    size_t len;
    int err;
    oe_result_t uStatus;

    uStatus = GetTrustedFileInBuffer(trustedLocation, &ptr, &len);
    if (uStatus != OE_OK) {
        return uStatus;
    }

    err = TEE_P_ExportFile(untrustedLocation, ptr, len);

    // Free the buffer.
    oe_free(ptr);

    return err;
}

oe_result_t
SaveBufferToFile(
    _In_z_ const char* destinationLocation, 
    _In_reads_bytes_(len) const void* ptr, 
    _In_ size_t len, 
    _In_ int addToManifest)
{
Tcps_InitializeStatus(Tcps_Module_Helper_t, "SaveBufferToFile");

    uStatus = TEE_P_SaveBufferToFile(destinationLocation, ptr, len);
    DMSG("SaveBufferToFile: TEE_P_SaveBufferToFile returned %#x\n", uStatus);
    Tcps_GotoErrorIfBad(uStatus);
    
    if (addToManifest) {
        uStatus = AppendFilenameToManifest(destinationLocation);
        DMSG("SaveBufferToFile: AppendFilenameToManifest returned %#x\n", uStatus);
        Tcps_GotoErrorIfBad(uStatus);
    }

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

int 
DeleteManifest(
    const char* manifestFilename)
{
    HANDLE hFindFile;
    WIN32_FIND_DATA data;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "DeleteManifest");

    hFindFile = FindFirstFile(manifestFilename, &data);
    if (hFindFile == INVALID_HANDLE_VALUE) {
        /* No manifest exists. */
        Tcps_ReturnStatusCode;
    }

    do {
        char fullname[256], *p;
        strcpy_s(fullname, sizeof(fullname), manifestFilename);

        /* Back up to last / or \ */
        p = fullname + strlen(fullname);
        while (p > fullname && p[-1] != '\\' && p[-1] != '/') {
            p--;
        }
        *p = 0;

        strcat_s(fullname, sizeof(fullname), data.cFileName);
        
        if (oe_remove(OE_FILE_SECURE_BEST_EFFORT, fullname) == -1) {
            uStatus = OE_FAILURE;
            Tcps_GotoError;
        }
    } while (FindNextFile(hFindFile, &data));

    FindClose(hFindFile);

    if (oe_remove(OE_FILE_SECURE_BEST_EFFORT, manifestFilename) == -1) {
        uStatus = OE_FAILURE;
        Tcps_GotoError;
    }

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    FindClose(hFindFile);
Tcps_FinishErrorHandling;
}

/* OpteeCalls supports less than 4k RPC input size */
#define MAXIMUM_OPTEE_CALLS_RPC_INPUT_SIZE      ((4 * 1024) - 512)

oe_result_t TEE_P_ExportFile(
    _In_z_ const char* untrustedLocation,
    _In_reads_bytes_(len) const char* ptr,
    _In_ size_t len)
{
    Tcps_Boolean appendToExistingFile;
    size_t currentWriteSize;
    oe_result_t result;
    unsigned int retval;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_ExportFile");

    Tcps_Trace(
        Tcps_TraceLevelDebug, 
        "TEE_P_ExportFile: ptr = %p, len = %#x, target = %s\n", 
        ptr, 
        len, 
        untrustedLocation);

    appendToExistingFile = Tcps_False;

    while (len > 0) {
        currentWriteSize = ((len > MAXIMUM_OPTEE_CALLS_RPC_INPUT_SIZE) ? 
            MAXIMUM_OPTEE_CALLS_RPC_INPUT_SIZE : len);

        result = ocall_ExportFile(
            &retval,
            untrustedLocation,
            appendToExistingFile,
            ptr, 
            currentWriteSize);

        uStatus = retval;

        Tcps_GotoErrorIfBad(result);
        Tcps_GotoErrorIfBad(uStatus);

        len -= currentWriteSize;
        ptr += currentWriteSize;
        appendToExistingFile = Tcps_True;
    }

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

/*===========================================================================================*/
/** @brief Imports a file into a secure location.                                            */
/*===========================================================================================*/
oe_result_t 
TEE_P_ImportFile(
    const char* destinationLocation, 
    const char* sourceLocation, 
    int addToManifest)
{
    oe_result_t result;
    GetUntrustedFileSize_Result sizeResult;
    GetUntrustedFileContent_Result contentResult;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_ImportFile");

    DMSG("TEE_P_ImportFile(%s -> %s, addToManifest = %d)\n", sourceLocation, destinationLocation, addToManifest);

    result = ocall_GetUntrustedFileSize(&sizeResult, sourceLocation);
    uStatus = sizeResult.status;
    DMSG("TEE_P_ImportFile: ocall_GetUntrustedFileSize returned result = %#x, uStatus = %#x\n", result, uStatus);
    Tcps_GotoErrorIfBad(result);
    Tcps_GotoErrorIfBad(uStatus);
    Tcps_GotoErrorIfTrue(sizeResult.fileSize <= 0, OE_FAILURE);
    Tcps_GotoErrorIfTrue(sizeResult.fileSize > sizeof(contentResult.content), OE_FAILURE);

    result = ocall_GetUntrustedFileContent(
        &contentResult,
        sourceLocation,
        sizeResult.fileSize);
    uStatus = contentResult.status;
    DMSG("TEE_P_ImportFile: ocall_GetUntrustedFileContent returned result = %#x, uStatus = %#x\n", result, uStatus);
    Tcps_GotoErrorIfBad(result);
    Tcps_GotoErrorIfBad(uStatus);

    uStatus = SaveBufferToFile(destinationLocation, contentResult.content, sizeResult.fileSize, addToManifest);
    DMSG("TEE_P_ImportFile: SaveBufferToFile returned uStatus = %#x\n", uStatus);
    Tcps_GotoErrorIfBad(uStatus);

    DMSG("TEE_P_ImportFile: uStatus = %#x\n", uStatus);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    DMSG("TEE_P_ImportFile: uStatus = %#x\n", uStatus);
Tcps_FinishErrorHandling;
}

int _mkdir(const char *dirname)  
{
    int crtError = 0;
    oe_result_t result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "_mkdir");

    result = ocall_mkdir(&crtError, dirname);
    Tcps_GotoErrorIfBad(result);

    return crtError;

Tcps_BeginErrorHandling;
    return EINVAL;
Tcps_FinishErrorHandling;
}
