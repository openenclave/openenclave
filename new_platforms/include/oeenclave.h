/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
#error include <openenclave/enclave.h> instead of including oeenclave.h directly
#endif

#ifndef OE_SIMULATE_OPTEE
#include <stdio.h>
#endif
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifdef OE_SIMULATE_OPTEE
#include <sal.h>
#include "optee/enclave/Simulator/oeenclave.h"
#endif

#include <openenclave/bits/result.h>
#include "tcps.h"

typedef int64_t __int64_t;
typedef uint64_t __uint64_t;
typedef uint32_t __uint32_t;
#include <sys/types.h>

#ifdef LINUX
#include "sal_unsup.h"
#else
#include <sal.h>
#endif

#define STRUNCATE 80

#ifndef INVALID_HANDLE_VALUE
typedef void* HANDLE;
#define INVALID_HANDLE_VALUE ((HANDLE)(-1LL))
#endif

#if !defined(DWORD) && !defined(_TCHAR_DEFINED)
typedef char TCHAR;
#define _TCHAR_DEFINED
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned long u_long;
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

struct _stat
{
    unsigned int st_dev;
    unsigned short st_ino;
    unsigned short st_mode;
    short st_nlink;
    short st_uid;
    short st_gid;
    unsigned int st_rdev;
    long st_size;
    __uint64_t st_atime;
    __uint64_t st_mtime;
    __uint64_t st_ctime;
};

int _stat(_In_z_ const char* path, _Out_ struct _stat* buffer);

#if !defined(_SYSINFOAPI_H_)
__uint32_t GetTickCount(void);

__uint32_t GetCurrentThreadId(void);

typedef struct _WIN32_FIND_DATA
{
    char cFileName[260];
} WIN32_FIND_DATA, *PWIN32_FIND_DATA, *LPWIN32_FIND_DATA;
#endif

#ifndef ERROR_NO_MORE_FILES
#define ERROR_NO_MORE_FILES 18
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
#endif /* !_APISETFILE_ */

#ifndef _ERRHANDLING_H_
void SetLastError(_In_ DWORD dwErrCode);
#endif /* !_ERRHANDLING_H_ */

oe_result_t SaveBufferToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len,
    _In_ int addToManifest);

oe_result_t GenerateKeyAndCertificate(
    _In_z_ const char* commonName,
    _In_z_ const char* certificateUri,
    _In_z_ const char* hostName,
    _In_z_ const char* keyFileName,
    _In_z_ const char* certificateFileName,
    _In_z_ const char* certificateFileNameExported,
    _In_ unsigned char isRsa);

oe_result_t GetTrustedFileSize(
    _In_z_ const char* trustedFilePath,
    _Out_ int64_t* fileSize);

oe_result_t GetTrustedFileInBuffer(
    _In_z_ const char* trustedLocation,
    _Outptr_ char** pBuffer,
    _Out_ size_t* pLen);

void FreeTrustedFileBuffer(_In_ char* buffer);

int DeleteManifest(_In_z_ const char* manifestFilename);

int AppendToFile(
    _In_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len);

int AppendToManifest(
    _In_z_ const char* manifestLocation,
    _In_z_ const char* filename);

int AppendFilenameToManifest(_In_z_ const char* filename);

int ExportPublicCertificate(
    _In_z_ const char* sourceLocation,
    _In_z_ const char* destinationPath);

int _mkdir(_In_z_ const char* dirname);

int ExportFile(
    _In_z_ const char* trustedLocation,
    _In_z_ const char* untrustedLocation);

oe_result_t Provision_Certificate(
    _In_z_ const char* destinationLocation,
    _In_z_ const char* sourceLocation);

/*************************************************************/

/* Prototypes that must be implemented by files specific to each TEE. */
oe_result_t TEE_P_SaveBufferToFile(
    _In_z_ const char* destinationLocation,
    _In_reads_bytes_(len) const void* ptr,
    _In_ size_t len);
oe_result_t TEE_P_ExportPublicCertificate(
    _In_z_ const char* destinationPath,
    _Out_writes_(len) char* ptr,
    _In_ size_t len);
oe_result_t TEE_P_ExportFile(
    _In_z_ const char* untrustedLocation,
    _In_reads_bytes_(len) const char* ptr,
    _In_ size_t len);
oe_result_t TEE_P_ImportFile(
    _In_z_ const char* destinationLocation,
    _In_z_ const char* sourceLocation,
    _In_ int addToManifest);

/* The caller is responsible for freeing the buffer after calling this. */
void* TcpsCreateTeeBuffer(_In_ int a_BufferSize);
oe_result_t TcpsGetTeeBuffer(
    _In_ void* a_hTeeBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize);
void TcpsFreeTeeBuffer(_In_ void* a_hTeeBuffer);

/* The caller is responsible for freeing the buffer after calling this. */
oe_result_t TcpsPushDataToReeBuffer(
    _In_reads_bytes_(a_BufferSize) const uint8_t* a_Buffer,
    _In_ size_t a_BufferSize,
    _Out_ void** a_phReeBuffer);

oe_result_t TcpsPullDataFromReeBuffer(
    _In_ void* a_hReeBuffer,
    _Out_writes_bytes_all_(a_BufferSize) uint8_t* a_Buffer,
    _In_ size_t a_BufferSize);

void TcpsFreeReeBuffer(_In_ void* a_hReeBuffer);

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((long)(void*)&(((type*)0)->field))
#endif
