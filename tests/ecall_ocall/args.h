// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

struct EncSetEnclaveIdArg
{
    OE_Result result;     // Out
    unsigned id;          // In
    const void* baseAddr; // Out
};

struct EncParallelExecutionArg
{
    OE_Result result;           // Out
    unsigned enclaveId;         // In
    unsigned flowId;            // In
    volatile unsigned* counter; // Inout
    volatile unsigned* release; // In
};

/*
 * Used for recursion tests as in/outcall/out buffer in host memory. Host
 * provides fresh one with each new recursion.
 */
struct EncRecursionArg
{
    unsigned enclaveId;             // In
    unsigned flowId;                // In
    unsigned recursionsLeft;        // InOut
    unsigned initialCount : 31;     // InOut
    unsigned isRotatingEnclave : 1; // In
    uint32_t crc;                   // InOut
};

struct EncTestNonExistingFunctionArg
{
    OE_Result result;         // Out
    const char* functionName; // In
};

enum
{
    TAG_START_HOST,
    TAG_END_HOST,
    TAG_START_ENC,
    TAG_END_ENC,
};
