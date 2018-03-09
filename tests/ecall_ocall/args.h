// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

struct TestEcallOcallSetEncIdArg
{
    OE_Result Result;     // Out
    unsigned Id;          // In
    const void* BaseAddr; // Out
};

struct TestEcallOcallParArg
{
    OE_Result Result;           // Out
    unsigned EnclaveNr;         // In
    unsigned FlowId;            // In
    volatile unsigned* Counter; // Inout
    volatile unsigned* Release; // In
};

/*
 * Used for recursion tests as in/outcall/out buffer in host memory. Host
 * provides fresh one with each new recursion.
 */
struct TestEcallOcallRecArg
{
    unsigned EnclaveNr;      // In
    unsigned FlowId;         // In
    unsigned RecursionsLeft; // InOut
    unsigned IsInitial;      // InOut
    uint32_t Crc;            // InOut
};

struct TestEcallOcallNAArg
{
    OE_Result Result;         // Out
    const char* FunctionName; // In
};

enum
{
    TAG_START_HOST,
    TAG_END_HOST,
    TAG_START_ENC,
    TAG_END_ENC,
};
