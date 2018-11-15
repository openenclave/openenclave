/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <memory.h>
#include <stdlib.h>
#include <windows.h>
#include <tee_api.h>
#include <tee_api_defines_extensions.h>

void *TEE_Malloc(uint32_t size, uint32_t hint)
{
    return malloc(size);
}

void TEE_Free(void* buffer)
{
    free(buffer);
}

void* __cdecl memcpy(
    void *dest,
    const void *src,
    size_t count)
{
    const char *csrc = (const char *)src;
    char *cdest = (char *)dest;
    size_t i;

    for (i = 0; i < count; i++) {
        cdest[i] = csrc[i];
    }
    return dest;
}

void* __cdecl memset(
    void *dest,  
    int c,  
    size_t count)  
{
    char *cdest = (char *)dest;
    size_t i;

    for (i = 0; i < count; i++) {
        cdest[i] = 0;
    }
    return dest;
}

void __assert()
{
}

TEE_Result TEE_CheckMemoryAccessRights(
    uint32_t accessFlags,
    void* buffer,
    uint32_t size)
{
    if (accessFlags & TEE_MEMORY_ACCESS_SECURE) {
        if ((uint32_t)buffer < 0x1000) {
            // This is a handle to secure world memory.
            return TEE_ERROR_ACCESS_DENIED;
        }

        // We don't currently have a way to tell whether the address is
        // a normal world address pointer or a secure world address pointer.
        // Since generated code only calls this with secure world pointers,
        // we'll just treat it as a secure world pointer in the OP-TEE
        // simulator.
        return TEE_SUCCESS;
    }

    if (accessFlags & TEE_MEMORY_ACCESS_NONSECURE) {
        // We don't currently have a way to tell whether the address is
        // a normal world address pointer or a secure world address pointer.
        // Since generated code only calls this with normal world pointers,
        // we'll just treat it as a normal world pointer in the OP-TEE
        // simulator.
        return TEE_SUCCESS;
    }

    /* We currently assume that only generated code calls this API,
     * and that it only does so with pointers it can actually access.
     */
    return TEE_SUCCESS;
}
