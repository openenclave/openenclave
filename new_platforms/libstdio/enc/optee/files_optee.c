/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#define _CRT_FUNCTIONS_REQUIRED 0
#include <openenclave/bits/stdio.h>
#include <stdlib.h>
#include <trace.h>
#include <string.h>
#include <tee_api.h>
#include <inttypes.h>

#include <tcps_string_t.h>
#include <stdio_t.h>
#undef errno
#include "enclavelibc.h"

#include <mbedtls/sha512.h>

typedef struct _OPTEE_FILE {
    TEE_ObjectHandle hObject;
    int iEof;
    int iError;
} OPTEE_FILE;

/* We currently use a manifest in a persistent object rather than just enumerating all persistent objects,
 * since it is similar to what we do for SGX, allows easily exporting the list of secured files, and allows
 * grouping by "directory".
 */
#define USE_MANIFEST_FILES

int errno = 0;

/* OP-TEE secure storage (RPMB) is not quite a filesystem: there are no
 * directories and there are no file names. Instead, one stores objects, each
 * of which is identified by an at most 64-byte long byte sequence. This byte
 * sequence need not be a sensible string; it is merely treated as a (void *).
 * Seeing as oe_fopen(...) is used with file paths and that these can be longer
 * than 64 characters (i.e. bytes), we don't pass the file path down to OP-TEE.
 * Instead, we hash it first using SHA-512, which conveniently generates a
 * 64-byte long digest and use that as the object ID.
 * 
 * NOTE: This breaks file enumeration.
 */
static void sha512( const unsigned char *input, size_t ilen,
             unsigned char output[64], int is384 )
{
    mbedtls_sha512_context ctx;

    mbedtls_sha512_init( &ctx );
    mbedtls_sha512_starts( &ctx, is384 );
    mbedtls_sha512_update( &ctx, input, ilen );
    mbedtls_sha512_finish( &ctx, output );
    mbedtls_sha512_free( &ctx );
}

static int oe_optee_fclose(
    intptr_t stream)
{
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;
    Tcps_Trace(Tcps_TraceLevelDebug, "fclose(%p) called\n", (fp)? fp->hObject : NULL);
    TEE_CloseObject(fp->hObject);
    fp->hObject = NULL;
    oe_free(fp);

    return 0;
}

static int oe_optee_feof(
    intptr_t stream)
{
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;
    return fp->iEof;
}

static int oe_optee_ferror(
    intptr_t stream)
{
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;
    return fp->iError;
}

static int oe_optee_fflush(
    intptr_t stream)
{
    /* Nothing to do.  OP-TEE has no flush function, so we assume data is automatically flushed. */
    (void)stream;

    return 0;
}

#ifdef _MSC_VER
#define SIZET_FMT "Iu"
#else
#define SIZET_FMT "zu"
#endif

static size_t oe_optee_fread(
    void* buffer,
    size_t size,
    size_t count,
    intptr_t stream)
{
    TEE_Result result;
    uint32_t uBytesRead;
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;

    if ((size * count) > UINT32_MAX) {
        EMSG("fread size %" SIZET_FMT " too large\n", size * count);
        return 0;
    }

    Tcps_Trace(Tcps_TraceLevelDebug, "fread hObject %p size %u\n", fp->hObject, (uint32_t)(size * count));

    result = TEE_ReadObjectData(fp->hObject,
                                buffer,
                                (uint32_t)(size * count),
                                &uBytesRead);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_ReadObject returned error %x\n", result);
        return 0;
    }

    if (uBytesRead == 0) {
        fp->iEof = TRUE;
    }

    return uBytesRead / size;
}

static int oe_optee_fseek(
    intptr_t stream,
    long offset,
    int origin)
{
    TEE_Result result;
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;

    Tcps_Trace(Tcps_TraceLevelDebug, "fseek(%p, %ld, %d) called\n", (fp)? fp->hObject : NULL, offset, origin);

    result = TEE_SeekObjectData(fp->hObject, offset, origin);
    if (result == TEE_SUCCESS) {
        fp->iEof = FALSE;
    } else {
        EMSG("TEE_SeekObjectData returned error %x\n", result);
    }
    return result;
}

static long oe_optee_ftell(
    intptr_t stream)
{
    TEE_ObjectInfo info;
    TEE_Result result;
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;

    Tcps_Trace(Tcps_TraceLevelDebug, "ftell(%p) called\n", (fp)? fp->hObject : NULL);

    result = TEE_GetObjectInfo1(fp->hObject, &info);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1 returned error %x\n", result);
        errno = EINVAL;
        return -1;
    }
    return info.dataPosition;
}

static size_t oe_optee_fwrite(
    const void* buffer,
    size_t size,
    size_t count,
    intptr_t stream)
{
    TEE_Result result;
    OPTEE_FILE* fp = (OPTEE_FILE*)stream;

    Tcps_Trace(Tcps_TraceLevelDebug, "fwrite(%p, %d, %d) called\n", (fp)? fp->hObject : NULL, size, count);

    result = TEE_WriteObjectData(fp->hObject, buffer, size * count);
    if (result != TEE_SUCCESS) {
        EMSG("TEE_WriteObjectData returned error %x\n", result);
        return 0;
    }
    return count;
}

/*
 * The fgets function reads a string from the input stream argument and stores it in str. fgets reads 
 * characters from the current stream position to and including the first newline character, to the end 
 * of the stream, or until the number of characters read is equal to n - 1, whichever comes first. The 
 * result stored in str is appended with a null character. The newline character, if read, is included 
 * in the string.
 */
static char* oe_optee_fgets(
    char* str,
    int n,
    intptr_t stream)
{
    /* TODO: stop reading when we see a newline.  */
    size_t sz = oe_optee_fread(str, 1, n, stream);
    if (oe_optee_ferror(stream)) {
        return NULL;
    }
    (void)sz;
    return str;
}

static oe_file_provider_t oe_optee_file_provider = {
    oe_optee_fclose,
    oe_optee_feof,
    oe_optee_ferror,
    oe_optee_fflush,
    oe_optee_fgets,
    NULL, // Use default fputs wrapper.
    oe_optee_fread,
    oe_optee_fseek,
    oe_optee_ftell,
    oe_optee_fwrite,
};

OE_FILE* oe_fopen_OE_FILE_SECURE_HARDWARE(
    const char* filename,
    const char* mode)
{
    unsigned char objectID[64];
    sha512((const unsigned char *)filename, strlen(filename), objectID, 0);

    TEE_Result result = TEE_SUCCESS;
    OPTEE_FILE* fp = oe_malloc(sizeof(*fp));
    if (fp == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    Tcps_Trace(Tcps_TraceLevelDebug, "fopen('%s', '%s') called\n", filename, mode);

    fp->iEof = fp->iError = 0;
    if ((strcmp(mode, "r") == 0) || (strcmp(mode, "rb") == 0)) {
        result = TEE_OpenPersistentObject(
            TEE_STORAGE_PRIVATE,
            objectID,
            64,
            TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
            &fp->hObject);
        if (result != TEE_SUCCESS) {
            Tcps_Trace(Tcps_TraceLevelWarning, "TEE_OpenPersistentObject for read returned error %x\n", result);
        }
    } else if (strcmp(mode, "a") == 0) {
        /* First see if the file already exists */
        result = TEE_OpenPersistentObject(
            TEE_STORAGE_PRIVATE,
            objectID,
            64,
            TEE_DATA_FLAG_ACCESS_WRITE,
            &fp->hObject);
        if (result == TEE_SUCCESS) {
            Tcps_Trace(Tcps_TraceLevelDebug, "TEE_OpenPersistentObject for write succeeded, seeking to end...\n");
            result = oe_fseek((OE_FILE*)fp, 0, TEE_DATA_SEEK_END); 
        } else {
            Tcps_Trace(Tcps_TraceLevelDebug, "TEE_OpenPersistentObject for write did not succeed, so trying to create a new file...\n");

            result = TEE_CreatePersistentObject(
                TEE_STORAGE_PRIVATE,
                objectID,
                64,
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
            objectID,
            64,
            TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
            TEE_HANDLE_NULL,
            NULL,
            0,
            &fp->hObject);
        if (result != TEE_SUCCESS) {
            DMSG("TEE_CreatePersistentObject returned error %x\n", result);
        }
    } else {
        oe_assert(FALSE);
    }
    
    Tcps_Trace(Tcps_TraceLevelDebug, "fopen returning result %x hObject %p\n", result, (fp) ? fp->hObject : NULL);
    
    if (result != TEE_SUCCESS) {
        errno = EACCES;
        oe_free(fp);
        return NULL;
    }

    OE_FILE* stream = oe_register_stream(&oe_optee_file_provider, (intptr_t)fp);
    if (stream == NULL) {
        oe_optee_fclose((intptr_t)fp);
        return NULL;
    }

    return stream;
}

int 
_stat(
    const char* path,
    struct _stat* buffer)
{
    oe_result_t result;
    int status;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "_stat");

    Tcps_GotoErrorIfTrue(sizeof(*buffer) != sizeof(ocall_struct_stat64i32), OE_FAILURE);

    result = ocall_stat64i32(&status, path, (ocall_struct_stat64i32*)buffer);
    Tcps_GotoErrorIfTrue(result != OE_OK, OE_FAILURE);
    Tcps_GotoErrorIfBad(status != 0);

    return 0;

Tcps_BeginErrorHandling;
    oe_assert(FALSE);
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
            oe_assert(FALSE); 
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

    fp = oe_fopen(OE_FILE_SECURE_HARDWARE, filename, "r");
    if (fp == NULL) {
        return -1;
    }

    // Read the first record from the file.
    result = oe_fread(findFileData, sizeof(*findFileData), 1, fp);
    if (result < 1) {
        oe_fclose(fp);
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
    OE_FILE* fp = (OE_FILE*) hFindFile;

    // Read the next record from the file.
    size_t result = oe_fread(findFileData, sizeof(*findFileData), 1, fp);
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
    OE_FILE* stream;
    int32_t result;

    if (hFindFile == INVALID_HANDLE_VALUE) {
        return TRUE;
    }
    stream = (OE_FILE*) hFindFile;
    result = oe_fclose(stream);
    return (result == 0);
}
#endif

oe_result_t GetTrustedFileSize(const char* trustedFilePath, int64_t* fileSize)
{
    TEE_Result result;
    TEE_ObjectHandle handle;
    TEE_ObjectInfo info;
    unsigned char objectID[64];
    oe_result_t tcpsStatus = OE_OK;

    *fileSize = 0;

    FMSG("trustedFilePath = %s", trustedFilePath);

    sha512((const unsigned char *)trustedFilePath, strlen(trustedFilePath), objectID, 0);

    result = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        objectID,
        64,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &handle);

    if (result != TEE_SUCCESS) {
        EMSG("TEE_OpenPersistentObject(%s) returned error %#x\n", trustedFilePath, result);
        tcpsStatus = OE_FAILURE;
        goto Done;
    }

    result = TEE_GetObjectInfo1(handle, &info);
    TEE_CloseObject(handle);

    if (result != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1(%s) returned error %#x\n", trustedFilePath, result);
        tcpsStatus = OE_FAILURE;
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
    FILE* fp = oe_fopen(OE_FILE_SECURE_HARDWARE, filename, "a");
    if (fp == NULL)
    {
        return errno;
    }
    writelen = oe_fwrite(ptr, 1, len, fp);

    oe_fclose(fp);
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

oe_result_t TEE_P_SaveBufferToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len)
{
    size_t writelen;
    FILE* fp = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_SaveBufferToFile");

    fp = oe_fopen(OE_FILE_SECURE_HARDWARE, destinationLocation, "w");
    Tcps_GotoErrorIfTrue(fp == NULL, OE_FAILURE);

    writelen = oe_fwrite(ptr, 1, len, fp);
    Tcps_GotoErrorIfTrue(writelen != len, OE_FAILURE);

    oe_fclose(fp);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    if (fp != NULL)
    {
        oe_fclose(fp);
    }
Tcps_FinishErrorHandling;
}

int oe_remove_OE_FILE_SECURE_HARDWARE(const char* filename)
{
    TEE_Result result;
    TEE_ObjectHandle hObject;

    unsigned char objectID[64];
    sha512((const unsigned char *)filename, strlen(filename), objectID, 0);

    result = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        objectID,
        64,
        TEE_DATA_FLAG_ACCESS_WRITE_META,
        &hObject);

    if (result == TEE_ERROR_ITEM_NOT_FOUND) {
        errno = ENOENT;
        return -1;
    }
    if (result != TEE_SUCCESS) {
        return -1;
    }

    result = TEE_CloseAndDeletePersistentObject1(hObject);

    return (result != TEE_SUCCESS) ? -1 : 0;
}
