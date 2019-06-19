// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SWITCHLESS_H_
#define _OE_SWITCHLESS_H_

#include <openenclave/bits/defs.h>
#include <openenclave/bits/lockless_queue.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_switchless_synchronous_ecall
{
    oe_lockless_queue_node _node;
    uint32_t lock;
    uint64_t table_id;
    uint64_t function_id;
    const uint8_t* input_buffer;
    size_t input_buffer_size;
    uint8_t* output_buffer;
    size_t output_buffer_size;
    size_t output_bytes_written;
    oe_result_t result;
} oe_switchless_synchronous_ecall_t;

typedef enum _oe_switchless_state
{
    OE_SWITCHLESS_STATE_STOPPED,
    OE_SWITCHLESS_STATE_STARTING,
    OE_SWITCHLESS_STATE_RUNNING,
    OE_SWITCHLESS_STATE_STOPPING,
} oe_switchless_state_t;

typedef struct _oe_switchless
{
    oe_switchless_state_t state;
    oe_lockless_queue ecall_queue;
} oe_switchless_t;

typedef struct _oe_enc_switchless_worker_start_args
{
    oe_switchless_t* switchless;
    oe_result_t result;
    uint32_t lock;
} oe_enc_switchless_worker_start_args_t;

OE_EXTERNC_END

#endif /* _OE_SWITCHLESS_H_ */
