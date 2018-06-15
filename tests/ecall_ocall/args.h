// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

struct EncSetEnclaveIdArg
{
    oe_result_t result;   // Out
    unsigned id;          // In
    const void* base_addr; // Out
};

struct EncParallelExecutionArg
{
    oe_result_t result;         // Out
    unsigned enclave_id;         // In
    unsigned flow_id;            // In
    volatile unsigned* counter; // Inout
    volatile unsigned* release; // In
};

/*
 * Used for recursion tests as in/outcall/out buffer in host memory. Host
 * provides fresh one with each new recursion.
 */
struct EncRecursionArg
{
    unsigned enclave_id;             // In
    unsigned flow_id;                // In
    unsigned recursions_left;        // InOut
    unsigned initial_count : 31;     // InOut
    unsigned is_rotating_enclave : 1; // In
    uint32_t crc;                   // InOut
};

struct EncTestCallHostFunctionArg
{
    oe_result_t result;       // Out
    const char* function_name; // In
};

enum
{
    TAG_START_HOST,
    TAG_END_HOST,
    TAG_START_ENC,
    TAG_END_ENC,
};
