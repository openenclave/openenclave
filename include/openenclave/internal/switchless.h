// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _SWITCHLESS_H_
#define _SWITCHLESS_H_

#include <openenclave/bits/result.h>
#include <openenclave/corelibc/stdint.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/lockless_queue.h>

#ifndef EXTERN
#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN
#endif
#endif

#ifdef _MSC_VER
typedef uint32_t volatile state_t;
typedef uint32_t volatile lock_t;
#elif defined __GNUC__
typedef uint32_t state_t;
typedef char lock_t;
#else
#error "unsupported"
#endif

enum ecall_type
{
    ET_SYNCHRONOUS,
    ET_ASYNCHRONOUS,
    ET_CALLBACK,
};

typedef struct _ecall_synchronous_data
{
    lock_t lock;
} ecall_synchronous_data;

typedef struct _ecall_asynchronous_data
{
} ecall_asynchronous_data;

typedef struct _ecall_callback_data
{
    void* callback;
} ecall_callback_data;

typedef struct _sc_queue_node
{
    lockless_queue_node _node;
    uint32_t type;
    union _data {
        ecall_synchronous_data sync;
        ecall_asynchronous_data async;
        ecall_callback_data callback;
    } data;
    uint32_t function_id;

    uint8_t* input_buffer;
    size_t input_buffer_size;
    uint8_t* output_buffer;
    size_t output_buffer_size;
    size_t output_bytes_written;
    oe_result_t result;

    // args has to be the final member
    // args is an implied member that doesn't really exist
    // uint8_t* args;
} sc_queue_node;

enum switchless_control_state
{
    SC_RUNNING,
    SC_STOPPING,
    SC_STOPPED,
    SC_EXITED,
};

typedef struct _switchless_control
{
    state_t _state;
    size_t count_limit;

    lockless_queue enc_queue;
    lockless_queue host_queue;
} switchless_control;

EXTERN void init_switchless_control(
    switchless_control* psc,
    uint32_t state,
    size_t count_limit);

EXTERN uint32_t sc_get_state(switchless_control* psc);

EXTERN void sc_set_state(switchless_control* psc, uint32_t state);

EXTERN void sc_push_enc_queue(switchless_control* psc, sc_queue_node* pnode);

EXTERN sc_queue_node* sc_pop_enc_queue(switchless_control* psc);

EXTERN void sc_push_host_queue(switchless_control* psc, sc_queue_node* pnode);

EXTERN sc_queue_node* sc_pop_host_queue(switchless_control* psc);

#endif // _SWITCHLESS_CONTROL_H_
