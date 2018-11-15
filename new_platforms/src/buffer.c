/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdlib.h>
#include <string.h>
#include <tcps.h>
#include <stdint.h>
#ifndef _In_
#include "sal_unsup.h"
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
                buffer->handle = (void*)(intptr_t)g_BufferSequenceNumber;
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

oe_result_t AppendToBuffer(
    _In_ void* a_hBuffer,
    _In_ oe_BufferChunk* a_Chunk)
{
    InternalBuffer_t* buffer = FindInternalBufferByHandle(a_hBuffer);
    if (buffer == NULL) {
        return OE_INVALID_PARAMETER;
    }

    // Resize buffer.
    size_t newSize = buffer->size + a_Chunk->size;
    if (newSize > INT32_MAX) {
        return OE_OUT_OF_MEMORY;
    }
    char* newPtr = realloc(buffer->ptr, newSize);
    if (newPtr == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    // Append chunk to buffer.
    memcpy(newPtr + buffer->size, a_Chunk->buffer, a_Chunk->size);
    buffer->size = (int)newSize;
    buffer->ptr = newPtr;

    return OE_OK;
}

void FreeInternalBuffer(_In_ InternalBuffer_t* buffer)
{
    free(buffer->ptr);
    buffer->ptr = NULL;
    buffer->size = 0;
    buffer->handle = NULL;
}

oe_result_t
GetBuffer(
    _In_ void* a_hBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize)
{
    InternalBuffer_t* buffer = FindInternalBufferByHandle(a_hBuffer);
    if (buffer == NULL) {
        *a_BufferSize = 0;
        *a_pBuffer = NULL;
        return OE_FAILURE;
    }
    *a_pBuffer = buffer->ptr;
    *a_BufferSize = buffer->size;
    return OE_OK;
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
