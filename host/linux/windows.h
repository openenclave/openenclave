// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_WINDOWS_H
#define _OE_HOST_WINDOWS_H

#include <openenclave/host.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FIELD_OFFSET(TYPE, Field) ((UINTN)(&(((TYPE*)0)->Field)))
#define PAGE_READWRITE 0x04
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE 0x00000020
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

typedef bool BOOL;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint64_t UINTN;
typedef void* LPVOID;
typedef void* HMODULE;
typedef const char* LPCSTR;
typedef void* HANDLE;
typedef UINT32 DWORD;
typedef size_t SIZE_T;
typedef DWORD* PDWORD;

#include "pe.h"

HMODULE LoadLibraryExA(LPCSTR path, HANDLE file, DWORD flags);

BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect);

BOOL FreeLibrary(HMODULE module);

#endif /* _OE_HOST_WINDOWS_H */
