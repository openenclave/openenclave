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

#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include <tcps_string_t.h>
#include <stdio_t.h>

#define DMSG printf

static int oe_sgx_fclose(
    intptr_t stream)
{
    int result = sgx_fclose((SGX_FILE*)stream);
    return result;
}

static int oe_sgx_feof(
    intptr_t stream)
{
    int result = sgx_feof((SGX_FILE*)stream);
    return result;
}

static int oe_sgx_ferror(
    intptr_t stream)
{
    int result = sgx_ferror((SGX_FILE*)stream);
    return result;
}

static int oe_sgx_fflush(
    intptr_t stream)
{
    return sgx_fflush((SGX_FILE*)stream);
}

static size_t oe_sgx_fread(
    void* buffer,
    size_t size,
    size_t count,
    intptr_t stream)
{
    size_t result = sgx_fread(buffer, size, count, (SGX_FILE*)stream);
    return result;
}

static int oe_sgx_fseek(
    intptr_t stream,
    long offset,
    int origin)
{
    return sgx_fseek((SGX_FILE*)stream, offset, origin);
}

static long oe_sgx_ftell(
    intptr_t stream)
{
    return (long)sgx_ftell((SGX_FILE*)stream);
}

static size_t oe_sgx_fwrite(
    const void* buffer,
    size_t size,
    size_t count,
    intptr_t stream)
{
    return sgx_fwrite(buffer, size, count, (SGX_FILE*)stream);
}

static int oe_sgx_fputs(const char* str, intptr_t stream)
{
    size_t len = strlen(str);
    size_t ret = sgx_fwrite(str, 1, len, (SGX_FILE*)stream);
    if (ret < len) {
        return EOF;
    }
    return (int)ret;
}

static char* oe_sgx_fgets(
    char* str,
    int n,
    intptr_t stream)
{
    size_t sz = sgx_fread(str, 1, n, (SGX_FILE*)stream);
    if (sgx_ferror((SGX_FILE*)stream)) {
        return NULL;
    }
    return str;
}

static oe_file_provider_t oe_sgx_file_provider = {
    oe_sgx_fclose,
    oe_sgx_feof,
    oe_sgx_ferror,
    oe_sgx_fflush,
    oe_sgx_fgets,
    oe_sgx_fputs,
    oe_sgx_fread,
    oe_sgx_fseek,
    oe_sgx_ftell,
    oe_sgx_fwrite,
};

OE_FILE *oe_fopen_OE_FILE_SECURE_ENCRYPTION(
    const char* path,
    const char* mode)
{
    SGX_FILE* fp = sgx_fopen_auto_key(path, mode);
    if (fp == NULL) {
        return NULL;
    }

    OE_FILE* result = oe_register_stream(&oe_sgx_file_provider, (intptr_t)fp);
    if (result == NULL) {
        sgx_fclose(fp);
        return NULL;
    }

    return result;
}

int _stat64i32(
    _In_z_ const char *path,
    _Out_ struct _stat64i32 *buffer)
{
    int result;
    sgx_status_t status = ocall_stat64i32(&result, path, (ocall_struct_stat64i32*)buffer);
    if (status != SGX_SUCCESS) {
        return -1;
    }
    return result;
}

int _stat(
    _In_z_ const char *path,
    _Out_ struct _stat *buffer)
{
    int result;

    if (sizeof(*buffer) != sizeof(ocall_struct_stat64i32)) {
        return -1;
    }
    sgx_status_t status = ocall_stat64i32(&result, path, (ocall_struct_stat64i32*)buffer);
    if (status != SGX_SUCCESS) {
        return -1;
    }
    return result;
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
    size_t writelen = sgx_fwrite(ptr, 1, len, fp);

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
    DMSG("TEE_P_SaveBufferToFile: sgx_fwrite(len = %zu) returned writelen = %zu\n", len, writelen);
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

int oe_remove_OE_FILE_SECURE_ENCRYPTION(const char* filename)
{
    return sgx_remove(filename);
}

#ifdef OE_USE_OPTEE
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
    return (__uint32_t)tid;
}
