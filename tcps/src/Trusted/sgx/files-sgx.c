/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <sgx_trts.h>
#include <sgx_tprotected_fs.h>
#include <sgx_thread.h>

#include <tcps_stdio_t.h>
#include <tcps_string_t.h>
#include <oeoverintelsgx_t.h>

#define DMSG printf

int fclose(
    FILE *stream)
{
    int result = sgx_fclose(stream);
    return result;
}

int feof(
    FILE *stream)
{
    int result = sgx_feof(stream);
    return result;
}

int ferror(
    FILE *stream)
{
    int result = sgx_ferror(stream);
    return result;
}

int fflush(
    FILE *stream)
{
    return sgx_fflush(stream);
}

FILE *fopen(
    const char *filename,
    const char *mode)
{
    FILE* result = sgx_fopen_auto_key(filename, mode);
    return result;
}

size_t fread(
    void *buffer,
    size_t size,
    size_t count,
    FILE *stream)
{
    size_t result = sgx_fread(buffer, size, count, stream);
    return result;
}

int fseek(
    FILE *stream,
    long offset,
    int origin)
{
    return sgx_fseek(stream, offset, origin);
}

long ftell(
    FILE *stream)
{
    return (long)sgx_ftell(stream);
}

size_t fwrite(
    const void *buffer,
    size_t size,
    size_t count,
    FILE *stream)
{
    return sgx_fwrite(buffer, size, count, stream);
}

int fputs(const char *str, FILE *stream)
{
    int len = strlen(str);
    int ret = sgx_fwrite(str, 1, len, stream);
    if (ret < len) {
        return EOF;
    }
    return ret;
}

char *fgets(
    char *str,
    int n,
    FILE *stream)
{
    size_t sz = sgx_fread(str, 1, n, stream);
    if (sgx_ferror(stream)) {
        return NULL;
    }
    return str;
}

int _stat64i32(
    _In_z_ const char *path,
    _Out_ struct _stat64i32 *buffer)
{
    oe_buffer256 pathBuffer;
    stat64i32_Result result;

    COPY_BUFFER_FROM_STRING(pathBuffer, path);

    sgx_status_t status = ocall_stat64i32(&result, pathBuffer);
    if (status != SGX_SUCCESS) {
        return -1;
    }
    *buffer = *((struct _stat64i32*)&result.buffer);
    return result.status;
}

int _stat(
    _In_z_ const char *path,
    _Out_ struct _stat *buffer)
{
    stat64i32_Result result;
    oe_buffer256 pathBuffer;

    if (sizeof(*buffer) != sizeof(ocall_struct_stat64i32)) {
        return -1;
    }
    COPY_BUFFER_FROM_STRING(pathBuffer, path);
    sgx_status_t status = ocall_stat64i32(&result, pathBuffer);
    if (status != SGX_SUCCESS) {
        return -1;
    }
    *buffer = *(struct _stat*)&result.buffer;
    return result.status;
}

int FindFirstFileInternal(
    HANDLE* hFindFile,
    const char* dirSpec,
    WIN32_FIND_DATA* findFileData)
{
    *hFindFile = INVALID_HANDLE_VALUE;
    memset(findFileData, 0, sizeof(*findFileData));

    // Compute a filename from the dirSpec.   path/*.der becomes path/manifest
    char filename[256];
    const char* p = strstr(dirSpec, "*.");
    if (p == NULL) {
        strcpy_s(filename, sizeof(filename), dirSpec);
    } else {
        strncpy_s(filename, sizeof(filename), dirSpec, p - dirSpec);
        filename[p - dirSpec] = 0;
        strcat_s(filename, sizeof(filename), "manifest");
    }
    FILE* fp = sgx_fopen_auto_key(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    // Read the first record from the file.
    size_t result = sgx_fread(findFileData, sizeof(*findFileData), 1, fp);
    if (result < 1) {
        sgx_fclose(fp);
        return -1;
    }

    *hFindFile = (HANDLE) fp;
    return 0;
}

/* Returns 0 on success, errno on error. */
int FindNextFileInternal(HANDLE hFindFile, WIN32_FIND_DATA* findFileData)
{
    SGX_FILE* fp = (SGX_FILE*) hFindFile;

    // Read the next record from the file.
    size_t result = sgx_fread(findFileData, sizeof(*findFileData), 1, fp);
    if (result < 1) {
        return ERROR_NO_MORE_FILES;
    }
    return 0;
}

int FindCloseInternal(HANDLE hFindFile)
{
    if (hFindFile == INVALID_HANDLE_VALUE) {
        return TRUE;
    }
    SGX_FILE* fp = (SGX_FILE*) hFindFile;
    int32_t result = sgx_fclose(fp);
    return (result == 0);
}

oe_result_t GetTrustedFileSize(const char* trustedFilePath, int64_t *fileSize)
{
    SGX_FILE* fp = sgx_fopen_auto_key(trustedFilePath, "r");
    if (fp == NULL) {
        return OE_FAILURE;
    }

    // fseek using SEEK_END doesn't seem to work, so we have to read a block at a time
    // until we get to the end.
    char buffer[4096];
    size_t len, cumul = 0;

    for (;;) {
        len = sgx_fread(buffer, 1, sizeof(buffer), fp);
        if (len <= 0) {
            sgx_fclose(fp);
            *fileSize = cumul;
            return OE_OK;
        }
        cumul += len;
    }
    
    sgx_fclose(fp);

    *fileSize = cumul;
    return OE_OK;
}

int AppendToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len)
{
    const char* filename = destinationLocation;
    SGX_FILE* fp = sgx_fopen_auto_key(filename, "a");
    if (fp == NULL)
    {
        return errno;
    }
    int writelen = sgx_fwrite(ptr, 1, len, fp);

    sgx_fclose(fp);
    if (writelen != len) {
        return 1;
    }

#ifdef _DEBUG
    char exportedLocation[256];
    strcpy_s(exportedLocation, sizeof(exportedLocation), destinationLocation);
    strcat_s(exportedLocation, sizeof(exportedLocation), ".exported");
    ExportFile(destinationLocation, exportedLocation);
#endif

    return 0;
}

oe_result_t TEE_P_SaveBufferToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len)
{
    SGX_FILE* fp = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "TEE_P_SaveBufferToFile");

    // DMFIX
    // destinationLocation = "/PKI/SecureGateway/foo.der";
    // destinationLocation = "/PKI/foo.der";
    // DMFIX

    fp = sgx_fopen_auto_key(destinationLocation, "w");
    DMSG("TEE_P_SaveBufferToFile: sgx_fopen_auto_key(%s) returned fp = %p\n", destinationLocation, fp);
    Tcps_GotoErrorIfTrue(fp == NULL, OE_FAILURE);

    size_t writelen = sgx_fwrite(ptr, 1, len, fp);
    DMSG("TEE_P_SaveBufferToFile: sgx_fwrite(len = %u) returned writelen = %u\n", len, writelen);
    Tcps_GotoErrorIfTrue(writelen != len, OE_FAILURE);

    sgx_fclose(fp);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
    if (fp != NULL)
    {
        sgx_fclose(fp);
    }
Tcps_FinishErrorHandling;
}

oe_result_t DeleteFile(const char* filename)
{
Tcps_InitializeStatus(Tcps_Module_Helper_t, "DeleteFile");

    int result = sgx_remove(filename);

    if (errno != ENOENT) {
        Tcps_GotoErrorIfTrue(result != 0, OE_FAILURE);
    }
   
Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;
Tcps_FinishErrorHandling;
}

#ifdef USE_OPTEE
unsigned long _lrotl (unsigned long val, int shift)
{
    shift &= 0x1f;
    val = (val>>(0x20 - shift)) | (val << shift);
    return val;
}

unsigned long _lrotr(unsigned long value, int shift)
{
    shift &= 0x1f;
    value = (value << (0x20 - shift)) | (value >> shift);
    return value;
}
#endif

__uint32_t GetCurrentThreadId()
{
    sgx_thread_t tid = sgx_thread_self();
    return tid;
}
