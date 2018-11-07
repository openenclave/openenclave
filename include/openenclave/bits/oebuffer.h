/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#include <openenclave/bits/result.h>

typedef struct oe_BufferChunk {
    char buffer[1024];
    int size;
} oe_BufferChunk;

typedef struct oe_CreateBuffer_Result {
    oe_result_t uStatus;
    void* hBuffer;
} oe_CreateBuffer_Result;

typedef struct oe_buffer256 {
    char buffer[256];
} oe_buffer256;

typedef struct oe_buffer1024 {
    char buffer[1024];
} oe_buffer1024;

typedef struct oe_buffer4096 {
    char buffer[4096];
} oe_buffer4096;
