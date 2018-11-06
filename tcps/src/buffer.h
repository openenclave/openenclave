/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#include <openenclave/bits/oebuffer.h>

typedef struct InternalBuffer_t {
    void* handle;
    char* ptr;
    int size;
} InternalBuffer_t;

InternalBuffer_t* CreateInternalBuffer(_In_ int a_Size);

InternalBuffer_t* FindInternalBufferByHandle(_In_ void* hBuffer);

void* CreateBuffer(_In_ int a_BufferSize);

Tcps_StatusCode AppendToBuffer(
    _In_ void* a_hBuffer,
    _In_ oe_BufferChunk* a_Chunk);

Tcps_StatusCode
GetBuffer(
    _In_ void* a_hBuffer,
    _Outptr_ char** a_pBuffer,
    _Out_ int* a_BufferSize);

void FreeInternalBuffer(_In_ InternalBuffer_t* a_Buffer);

void FreeBuffer(_In_ void* a_hBuffer);
