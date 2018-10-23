/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error tcps_t.h should only be included with TRUSTED_CODE
#endif

#ifndef SIMULATE_TEE
#include <stdio.h>
#endif
#include <stddef.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>

#ifdef SIMULATE_TEE
# include "optee/Trusted/Simulator/tcps_t.h"
#endif

#include "tcps.h"

typedef int64_t __int64_t;
typedef uint64_t __uint64_t;
typedef uint32_t __uint32_t;

#ifndef __in_ecount
/* Support various SAL annotations as no-ops */
#define __in_ecount(x)
#define _In_z_
#define _In_
#define _Outptr_
#define _Outptr_opt_
#define _Out_
#define _In_reads_bytes_(x)
#define _Inout_
#define _Out_writes_(x)
#define _Out_writes_opt_z_(x)
#define _Out_writes_bytes_(x)
#define _In_opt_
#define _Inout_opt_
#define _Out_writes_bytes_to_(a, b)
#define _Out_writes_bytes_all_(a)
#endif

/* Support various SGX types, even for OP-TEE, so we can reuse the automatic
 * code generator from the SGX SDK.
 */
# include <sgx.h>
#if defined(USE_OPTEE)
# include "optee/TcpsRpcOptee.h"
#endif

#define STRUNCATE 80 

#ifndef INVALID_HANDLE_VALUE
typedef void* HANDLE;
# define INVALID_HANDLE_VALUE ((HANDLE)(-1LL))
#endif

#if !defined(DWORD) && !defined(_TCHAR_DEFINED)
typedef char TCHAR;
typedef int BOOL;
typedef uint32_t DWORD;
typedef unsigned long u_long;
#endif

#define TRUE 1
#define FALSE 0

struct _stat {
    unsigned int   st_dev;
    unsigned short st_ino;
    unsigned short st_mode;
    short          st_nlink;
    short          st_uid;
    short          st_gid;
    unsigned int   st_rdev;
    long           st_size;
    __uint64_t     st_atime;
    __uint64_t     st_mtime;
    __uint64_t     st_ctime;
};

int _stat(
    _In_z_ const char *path,
    _Out_ struct _stat *buffer);

#ifndef _SYSINFOAPI_H_
__uint32_t GetTickCount(void);

__uint32_t GetCurrentThreadId(void);

typedef struct _WIN32_FIND_DATA {
    char cFileName[260];
} WIN32_FIND_DATA, *PWIN32_FIND_DATA, *LPWIN32_FIND_DATA;
#endif

#ifndef ERROR_NO_MORE_FILES
# define ERROR_NO_MORE_FILES 18
#endif

int FindFirstFileInternal(
    HANDLE* hFindFile,
    _In_z_ const char* dirSpec,
    WIN32_FIND_DATA* findFileData);

int FindNextFileInternal(HANDLE hFindFile, WIN32_FIND_DATA* findFileData);

int FindCloseInternal(_In_ HANDLE hFindFile);

#ifndef _APISETFILE_
HANDLE FindFirstFile(
    _In_z_ const char* lpFileName,
    WIN32_FIND_DATA* lpFindFileData);

int FindNextFile(HANDLE hFindFile, WIN32_FIND_DATA* findFileData);

BOOL FindClose(_In_ HANDLE hFindFile);

BOOL DeleteFile(_In_z_ const char* filename);
#endif /* !_APISETFILE_ */

#ifndef _ERRHANDLING_H_
void SetLastError(_In_ DWORD dwErrCode);
#endif /* !_ERRHANDLING_H_ */

Tcps_StatusCode
SaveBufferToFile(
    _In_z_ const char* destinationLocation, 
    _In_reads_bytes_(len) const void* ptr, 
    _In_ size_t len, 
    _In_ int addToManifest);

Tcps_StatusCode
GenerateKeyAndCertificate(
    _In_z_ const char* commonName,
    _In_z_ const char* certificateUri,
    _In_z_ const char* hostName,
    _In_z_ const char* keyFileName,
    _In_z_ const char* certificateFileName,
    _In_z_ const char* certificateFileNameExported,
    _In_ unsigned char isRsa);

Tcps_StatusCode GetTrustedFileSize(
    _In_z_ const char* trustedFilePath,
    _Out_ int64_t *fileSize);

Tcps_StatusCode GetTrustedFileInBuffer(
    _In_z_ const char* trustedLocation, 
    _Outptr_ char** pBuffer,
    _Out_ size_t* pLen);

void FreeTrustedFileBuffer(
    _In_ char* buffer);

int DeleteManifest(
    _In_z_ const char* manifestFilename);

int AppendToFile(
    _In_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len);

int AppendToManifest(
    _In_z_ const char* manifestLocation,
    _In_z_ const char* filename);

int AppendFilenameToManifest(
    _In_z_ const char* filename);

int ExportPublicCertificate(
    _In_z_ const char* sourceLocation,
    _In_z_ const char* destinationPath);

int _mkdir(
    _In_z_ const char *dirname);

int ExportFile(
    _In_z_ const char* trustedLocation,
    _In_z_ const char* untrustedLocation);

Tcps_StatusCode Provision_Certificate(
    _In_z_ const char* destinationLocation, 
    _In_z_ const char* sourceLocation);

TCPS_DEPRECATED(int FillRandom(
    _Out_writes_bytes_all_(len) void* ptr,
    _In_ size_t len),
    "FillRandom is deprecated. Use oe_random() instead.");

TCPS_DEPRECATED(int Tcps_FillRandom(
    _Out_writes_bytes_all_(len) void* ptr,
    _In_ size_t len),
    "Tcps_FillRandom is deprecated. Use oe_random() instead.");

/*************************************************************/

/* Prototypes that must be implemented by files specific to each TEE. */
Tcps_StatusCode TEE_P_SaveBufferToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len);
Tcps_StatusCode TEE_P_ExportPublicCertificate(
    _In_z_ const char* destinationPath,
    _Out_writes_(len) char* ptr,
    _In_ size_t len);
Tcps_StatusCode TEE_P_ExportFile(
    _In_z_ const char* untrustedLocation,
    _In_reads_bytes_(len) const char* ptr,
    _In_ size_t len);
Tcps_StatusCode TEE_P_ImportFile(
    _In_z_ const char* destinationLocation,
    _In_z_ const char *sourceLocation,
    _In_ int addToManifest);

/* The caller is responsible for freeing the buffer after calling this. */
void* TcpsCreateTeeBuffer(_In_ int a_BufferSize);
Tcps_StatusCode TcpsGetTeeBuffer(
    _In_ void* a_hTeeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize);
void TcpsFreeTeeBuffer(_In_ void* a_hTeeBuffer);

/* The caller is responsible for freeing the buffer after calling this. */
Tcps_StatusCode
TcpsPushDataToReeBuffer(
    _In_reads_bytes_(a_BufferSize) const uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phReeBuffer);

Tcps_StatusCode
TcpsPullDataFromReeBuffer(
    _In_ void* a_hReeBuffer,
    _Out_writes_bytes_all_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize);

void TcpsFreeReeBuffer(_In_ void* a_hReeBuffer);

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((long)(void*)&(((type *)0)->field))
#endif

