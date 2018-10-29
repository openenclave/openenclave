/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef LINUX
#include "sal_unsup.h"
#endif
#include <stdlib.h>
#include <string.h>
#ifdef TRUSTED_CODE
# include "Trusted/TcpsCalls_t.h"
# include "tcps_t.h"
#else
# include "Untrusted/TcpsCalls_u.h"
# include "tcps_u.h"
#endif
#include "buffer.h"

#define MAX_BUFFERS 2

int g_BufferSequenceNumber = 0;
InternalBuffer_t g_BufferArray[MAX_BUFFERS] = {{ 0 }};

InternalBuffer_t* CreateInternalBuffer(_In_ int size)
{
    // Allocate a new buffer handle.
    for (int i = 0; i < MAX_BUFFERS; i++) {
        InternalBuffer_t* buffer = &g_BufferArray[i];
        if (buffer->ptr == NULL) {
            // We found a free buffer slot, use it.
            g_BufferSequenceNumber++;
            if (g_BufferSequenceNumber == 0) {
                // Handle rollover, never use a 0 value.
                g_BufferSequenceNumber++;
            }
            buffer->ptr = malloc(size);
            if (buffer->ptr != NULL) {
                buffer->handle = (void*)g_BufferSequenceNumber;
                buffer->size = size;
            }
            return buffer;
        }
    }

    return NULL;
}

InternalBuffer_t* FindInternalBufferByHandle(_In_ void* hBuffer)
{
    for (int i = 0; i < MAX_BUFFERS; i++) {
        if (g_BufferArray[i].handle == hBuffer) {
            return &g_BufferArray[i];
        }
    }
    return NULL;
}

Tcps_StatusCode AppendToBuffer(
    _In_ void* a_hBuffer,
    _In_ BufferChunk* a_Chunk)
{
    InternalBuffer_t* buffer = FindInternalBufferByHandle(a_hBuffer);
    if (buffer == NULL) {
        return Tcps_BadInvalidArgument;
    }

    // Resize buffer.
    size_t newSize = buffer->size + a_Chunk->size;
    char* newPtr = realloc(buffer->ptr, newSize);
    if (newPtr == NULL) {
        return Tcps_BadOutOfMemory;
    }

    // Append chunk to buffer.
    memcpy(newPtr + buffer->size, a_Chunk->buffer, a_Chunk->size);
    buffer->size = newSize;
    buffer->ptr = newPtr;

    return Tcps_Good;
}

void FreeInternalBuffer(_In_ InternalBuffer_t* buffer)
{
    free(buffer->ptr);
    buffer->ptr = NULL;
    buffer->size = 0;
    buffer->handle = NULL;
}

Tcps_StatusCode
GetBuffer(
    _In_ void* a_hBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize)
{
    InternalBuffer_t* buffer = FindInternalBufferByHandle(a_hBuffer);
    if (buffer == NULL) {
        *a_BufferSize = 0;
        *a_pBuffer = NULL;
        return Tcps_Bad;
    }
    *a_pBuffer = buffer->ptr;
    *a_BufferSize = buffer->size;
    return Tcps_Good;
}

void FreeBuffer(_In_ void* a_hBuffer)
{
    InternalBuffer_t* buffer = FindInternalBufferByHandle(a_hBuffer);
    if (buffer != NULL) {
        FreeInternalBuffer(buffer);
    }
}

void* CreateBuffer(_In_ int a_BufferSize)
{
    InternalBuffer_t* buffer = CreateInternalBuffer(a_BufferSize);
    if (buffer == NULL) {
        return NULL;
    }
    return buffer->handle;
}
