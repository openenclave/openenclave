/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#define _CRT_FUNCTIONS_REQUIRED 0
#include <tcps_stdio_t.h>
#include <stdlib.h>
#include <trace.h>
#include <string.h>

#include <tcps_string_t.h>
#include <TcpsCalls_t.h>
#undef errno

/* We currently use a manifest in a persistent object rather than just enumerating all persistent objects,
 * since it is similar to what we do for SGX, allows easily exporting the list of secured files, and allows
 * grouping by "directory".
 */
#define USE_MANIFEST_FILES

int errno = 0;

int fclose(
    OPTEE_FILE *stream)
{
    Tcps_Trace(Tcps_TraceLevelDebug, "fclose(%p) called\n", (stream)? stream->hObject : NULL);
    TEE_CloseObject(stream->hObject);
    stream->hObject = NULL;

    return 0;
}

int feof(
    FILE *stream)
{
    return stream->iEof;
}

int ferror(
    FILE *stream)
{
    return stream->iError;
}

int fflush(
    FILE *stream)
{
    /* Nothing to do.  OP-TEE has no flush function, so we assume data is automatically flushed. */
    (void)stream;

    return 0;
}

FILE* fopen(
    const char* filename,
    const char* mode)
{
    TEE_Result result = TEE_SUCCESS;
    FILE* fp = TCPS_ALLOC(sizeof(*fp));
    if (fp == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    
    Tcps_Trace(Tcps_TraceLevelDebug, "fopen('%s', '%s') called\n", filename, mode);

    fp->iEof = fp->iError = 0;
    if ((strcmp(mode, "r") == 0) || (strcmp(mode, "rb") == 0)) {
        result = TEE_OpenPersistentObject(
            TEE_STORAGE_PRIVATE,
            filename,
            strlen(filename),
            TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
            &fp->hObject);
        if (result != TEE_SUCCESS) {
            Tcps_Trace(Tcps_TraceLevelWarning, "TEE_OpenPersistentObject for read returned error %x\n", result);
        }
    } else if (strcmp(mode, "a") == 0) {
        /* First see if the file already exists */
        result = TEE_OpenPersistentObject(
            TEE_STORAGE_PRIVATE,
            filename,
            strlen(filename),
            TEE_DATA_FLAG_ACCESS_WRITE,
            &fp->hObject);
        if (result == TEE_SUCCESS) {
            Tcps_Trace(Tcps_TraceLevelDebug, "TEE_OpenPersistentObject for write succeeded, seeking to end...\n");
            result = fseek(fp, 0, TEE_DATA_SEEK_END); 
        } else {
            Tcps_Trace(Tcps_TraceLevelDebug, "TEE_OpenPersistentObject for write did not succeed, so trying to create a new file...\n");

            result = TEE_CreatePersistentObject(
                TEE_STORAGE_PRIVATE,
                filename,
                strlen(filename),
                TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
                TEE_HANDLE_NULL,
                NULL,
                0,
                &fp->hObject);
            if (result != TEE_SUCCESS) {
                EMSG("TEE_CreatePersistentObject returned error %x\n", result);
            }
        }
    } else if (strcmp(mode, "w") == 0) {
        result = TEE_CreatePersistentObject(
            TEE_STORAGE_PRIVATE,
            filename,
            strlen(filename),
            TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
            TEE_HANDLE_NULL,
            NULL,
            0,
            &fp->hObject);
        if (result != TEE_SUCCESS) {
            DMSG("TEE_CreatePersistentObject returned error %x\n", result);
        }
    } else {
        TCPS_ASSERT(FALSE);
    }
    
    Tcps_Trace(Tcps_TraceLevelDebug, "fopen returning result %x hObject %p\n", result, (fp) ? fp->hObject : NULL);
    
    if (result != TEE_SUCCESS) {
        errno = EACCES;
        TCPS_FREE(fp);
        fp = NULL;
    }
    return fp;
}

#ifdef _MSC_VER
#define SIZET_FMT "Iu"
#else
#define SIZET_FMT "zu"
#endif

size_t fread(
    void* buffer,
    size_t size,
    size_t count,
    FILE *stream)
{
    TEE_Result result;
    uint32_t uBytesRead;

    if ((size * count) > UINT32_MAX) {
        EMSG("fread size %" SIZET_FMT " too large\n", size * count);
        return 0;
    }

    Tcps_Trace(Tcps_TraceLevelDebug, "fread hObject %p size %u\n", stream->hObject, (uint32_t)(size * count));

    result = TEE_ReadObjectData(stream->hObject,
                                buffer,
                                (uint32_t)(size * count),
                                &uBytesRead);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_ReadObject returned error %x\n", result);
        return 0;
    }

    if (uBytesRead == 0) {
        stream->iEof = TRUE;
    }

    return uBytesRead / size;
}

int fseek(
    FILE *stream,
    long offset,
    int origin)
{
    TEE_Result result;

    Tcps_Trace(Tcps_TraceLevelDebug, "fseek(%p, %ld, %d) called\n", (stream)? stream->hObject : NULL, offset, origin);

    result = TEE_SeekObjectData(stream->hObject, offset, origin);
    if (result == TEE_SUCCESS) {
        stream->iEof = FALSE;
    } else {
        EMSG("TEE_SeekObjectData returned error %x\n", result);
    }
    return result;
}

long ftell(
    FILE *stream)
{
    TEE_ObjectInfo info;
    TEE_Result result;

    Tcps_Trace(Tcps_TraceLevelDebug, "ftell(%p) called\n", (stream)? stream->hObject : NULL);

    result = TEE_GetObjectInfo1(stream->hObject, &info);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1 returned error %x\n", result);
        errno = EINVAL;
        return -1;
    }
    return info.dataPosition;
}

size_t fwrite(
    const void *buffer,
    size_t size,
    size_t count,
    FILE *stream)
{
    TEE_Result result;

    Tcps_Trace(Tcps_TraceLevelDebug, "fwrite(%p, %d, %d) called\n", (stream)? stream->hObject : NULL, size, count);

    result = TEE_WriteObjectData(stream->hObject, buffer, size * count);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_WriteObjectData returned error %x\n", result);
        return 0;
    }
    return count;
}

int fputs(const char *str, FILE *stream)
{
    size_t bytesToWrite = strlen(str);
    size_t bytesWritten = fwrite(str, 1, bytesToWrite, stream);
    return (bytesWritten == bytesToWrite) ? 0 : -1;
}

/*
 * The fgets function reads a string from the input stream argument and stores it in str. fgets reads 
 * characters from the current stream position to and including the first newline character, to the end 
 * of the stream, or until the number of characters read is equal to n - 1, whichever comes first. The 
 * result stored in str is appended with a null character. The newline character, if read, is included 
 * in the string.
 */
char* fgets(
    char* str,
    int n,
    FILE* stream)
{
    /* TODO: stop reading when we see a newline.  The SGX code didn't do so and still worked so the demo
     * should still work without doing this todo.
     */
    size_t sz = fread(str, 1, n, stream);
    if (ferror(stream)) {
        return NULL;
    }
    (void)sz;
    return str;
}

int 
_stat(
    const char *path,
    struct _stat *buffer)
{
    sgx_status_t sgxStatus;
    buffer256 pathBuffer;
    stat64i32_Result result;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "_stat");

    Tcps_GotoErrorIfTrue(sizeof(*buffer) != sizeof(ocall_struct_stat64i32), Tcps_Bad);

    COPY_BUFFER_FROM_STRING(pathBuffer, path);

    sgxStatus = ocall_stat64i32(&result, pathBuffer);
    Tcps_GotoErrorIfTrue(sgxStatus != SGX_SUCCESS, Tcps_Bad);
    Tcps_GotoErrorIfBad(result.status != 0);
    memcpy(buffer, &result.buffer, sizeof(*buffer));

    return 0;

Tcps_BeginErrorHandling;
    TCPS_ASSERT(FALSE);
    return -1;
}

int FindFirstFileInternal(
    HANDLE* hFindFile,
    const char* dirSpec,
    WIN32_FIND_DATA* findFileData)
#ifndef USE_MANIFEST_FILES
{
    TEE_ObjectEnumHandle hEnumerator;
    TEE_Result result = TEE_AllocatePersistentObjectEnumerator(&hEnumerator);

    *hFindFile = INVALID_HANDLE_VALUE;
    if (result != TEE_SUCCESS) {
        EMSG("TEE_AllocatePersistentObjectEnumerator returned error %x\n", result);
        return -1;
    }

    result = TEE_StartPersistentObjectEnumerator(hEnumerator, TEE_STORAGE_PRIVATE);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_StartPersistentObjectEnumerator returned error %x\n", result);
        TEE_FreePersistentObjectEnumerator(hEnumerator);
        return -1;
    }

    *hFindFile = hEnumerator;

    for (;;) {
        char* wildcard;
        int wildcardIndex;

        result = FindNextFileInternal(hEnumerator, findFileData);
        if (result != 0) {
            TEE_FreePersistentObjectEnumerator(hEnumerator);
            return result;
        }

        wildcard = strchr(dirSpec, '*');
        if (wildcard == NULL) {
            /* Not implemented, not used by the demo. */
            TCPS_ASSERT(FALSE); 
            return -1;
        }

        wildcardIndex = wildcard - dirSpec;

        /* Verify that the filename starts with the right prefix. */
        if ((wildcardIndex > 0) && (strncmp(findFileData->cFileName, dirSpec, wildcardIndex) != 0)) {
            continue;
        }

        /* Verify that the filename ends with the right suffix. */
        if (findFileData->cFileName[wildcardIndex + 1] != '\0') {
            int suffixLength = strlen(dirSpec) - (wildcardIndex + 1);
            int fileNameLength = strlen(findFileData->cFileName);
            const char* fileNameSuffix = findFileData->cFileName + (fileNameLength - suffixLength);
            const char* dirSpecSuffix = dirSpec + wildcardIndex + 1;
            if (strcmp(fileNameSuffix, dirSpecSuffix) != 0) {
                continue;
            }
        }

        return 0;
    }
}
#else /* USE_MANIFEST_FILES */
{
    size_t result;
    char filename[256];
    const char* p;
    FILE *fp;

    *hFindFile = INVALID_HANDLE_VALUE;
    memset(findFileData, 0, sizeof(*findFileData));

    // Compute a filename from the dirSpec.   path/*.der becomes path/manifest
    p = strstr(dirSpec, "*.");
    if (p == NULL) {
        strcpy_s(filename, sizeof(filename), dirSpec);
    } else {
        strncpy_s(filename, sizeof(filename), dirSpec, p - dirSpec);
        filename[p - dirSpec] = 0;
        strcat_s(filename, sizeof(filename), "manifest");
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    // Read the first record from the file.
    result = fread(findFileData, sizeof(*findFileData), 1, fp);
    if (result < 1) {
        fclose(fp);
        return -1;
    }

    *hFindFile = (HANDLE) fp;
    return 0;
}
#endif

/* Returns 0 on success, errno on error. */
int FindNextFileInternal(HANDLE hFindFile, WIN32_FIND_DATA* findFileData)
#ifndef USE_MANIFEST_FILES
{
    char filename[TEE_OBJECT_ID_MAX_LEN + 1];
    TEE_ObjectInfo info;
    size_t filenameLength;
    TEE_Result result = TEE_GetNextPersistentObject(hFindFile, &info, filename, &filenameLength);
    if (result == TEE_ERROR_ITEM_NOT_FOUND) {
        return ERROR_NO_MORE_FILES;
    }
    if (result != TEE_SUCCESS) {
        EMSG("TEE_GetNextPersistentObject returned error %x\n", result);
        return -1;
    }

    filename[filenameLength] = '\0';

    strcpy_s(findFileData->cFileName, sizeof(findFileData->cFileName), filename);

    DMSG("FindNextFileInternal found %s\n", filename);

    return 0;
}
#else
{
    FILE* fp = (FILE*) hFindFile;

    // Read the next record from the file.
    size_t result = fread(findFileData, sizeof(*findFileData), 1, fp);
    if (result < 1) {
        return ERROR_NO_MORE_FILES;
    }
    return 0;
}
#endif

int FindCloseInternal(HANDLE hFindFile)
#ifndef USE_MANIFEST_FILES
{
    TEE_FreePersistentObjectEnumerator(hFindFile);
    return 0;
}
#else
{
    FILE* fp;
    int32_t result;

    if (hFindFile == INVALID_HANDLE_VALUE) {
        return TRUE;
    }
    fp = (FILE*) hFindFile;
    result = fclose(fp);
    return (result == 0);
}
#endif

Tcps_StatusCode GetTrustedFileSize(const char* trustedFilePath, int64_t *fileSize)
{
    TEE_Result result;
    TEE_ObjectHandle handle;
    TEE_ObjectInfo info;
    Tcps_StatusCode tcpsStatus = Tcps_Good;

    *fileSize = 0;

    FMSG("trustedFilePath = %s", trustedFilePath);

    result = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        trustedFilePath,
        strlen(trustedFilePath),
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &handle);

    if (result != TEE_SUCCESS) {
        EMSG("TEE_OpenPersistentObject(%s) returned error %#x\n", trustedFilePath, result);
        tcpsStatus = Tcps_Bad;
        goto Done;
    }

    result = TEE_GetObjectInfo1(handle, &info);
    TEE_CloseObject(handle);

    if (result != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1(%s) returned error %#x\n", trustedFilePath, result);
        tcpsStatus = Tcps_Bad;
        goto Done;
    }

    *fileSize = info.dataSize;

Done:

    return tcpsStatus;
}

int AppendToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len)
{
    size_t writelen;
    const char* filename = destinationLocation;
    FILE* fp = fopen(filename, "a");
    if (fp == NULL)
    {
        return errno;
    }
    writelen = fwrite(ptr, 1, len, fp);

    fclose(fp);
    if (writelen != len) {
        return 1;
    }

#ifdef _DEBUG
    {
        char exportedLocation[256];
        strcpy_s(exportedLocation, sizeof(exportedLocation), destinationLocation);
        strcat_s(exportedLocation, sizeof(exportedLocation), ".exported");
        ExportFile(destinationLocation, exportedLocation);
    }
#endif

    return 0;
}

Tcps_StatusCode TEE_P_SaveBufferToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len)
{
    size_t writelen;
    FILE* fp = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_SaveBufferToFile");

    fp = fopen(destinationLocation, "w");
    Tcps_GotoErrorIfTrue(fp == NULL, Tcps_BadUnexpectedError);

    writelen = fwrite(ptr, 1, len, fp);
    Tcps_GotoErrorIfTrue(writelen != len, Tcps_BadUnexpectedError);

    fclose(fp);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    if (fp != NULL)
    {
        fclose(fp);
    }
Tcps_FinishErrorHandling;
}

Tcps_StatusCode DeleteFile(const char* filename)
{
    TEE_Result result;
    TEE_ObjectHandle hObject;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "DeleteFile");

    result = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        filename,
        strlen(filename),
        TEE_DATA_FLAG_ACCESS_WRITE_META,
        &hObject);

    if (result == TEE_ERROR_ITEM_NOT_FOUND) {
        Tcps_Trace(Tcps_TraceLevelDebug, "DeleteFile: file doesn't exist: %s\n", filename);
        Tcps_ReturnStatusCode;
    }
    Tcps_GotoErrorIfTrue(result != TEE_SUCCESS, Tcps_Bad);

    result = TEE_CloseAndDeletePersistentObject1(hObject); 
    Tcps_GotoErrorIfTrue(result != TEE_SUCCESS, Tcps_Bad);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}
