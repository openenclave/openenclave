#ifndef _OE_HOST_WINDOWS_STUBS_H
#define _OE_HOST_WINDOWS_STUBS_H

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE 0x00000020
#define PAGE_READWRITE 0x04
#define FIELD_OFFSET(TYPE, Field) ((UINTN)(&(((TYPE*)0)->Field)))

typedef bool BOOL;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINTN;
typedef void* LPVOID;
typedef void* HMODULE;
typedef const char* LPCSTR;
typedef void* HANDLE;
typedef UINT32 DWORD;
typedef size_t SIZE_T;
typedef DWORD* PDWORD;

static __inline__ HMODULE LoadLibraryExA(
    LPCSTR lpLibFileName,
    HANDLE hFile,
    DWORD dwFlags)
{
    return NULL;
}

static __inline__ BOOL VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect)
{
    return false;
}

static __inline__ BOOL FreeLibrary(HMODULE hLibModule)
{
    return false;
}

#include "../3rdparty/gnu-efi/gnu-efi/gnu-efi-3.0/inc/x86_64/pe.h"

#endif /* _OE_HOST_WINDOWS_STUBS_H */
