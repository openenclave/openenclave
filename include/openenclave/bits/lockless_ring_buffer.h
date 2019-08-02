/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#ifndef _LOCKLESS_RING_BUFFER_H_
#define _LOCKLESS_RING_BUFFER_H_

#include <openenclave/bits/defs.h>
#include <stddef.h>

OE_EXTERNC_BEGIN

#ifdef _MSC_VER
typedef char* volatile data_ptr;
#elif defined __GNUC__
typedef char* data_ptr;
#endif /* _MSC_VER or __GNUC__ */

/* read me:
 * This implementation is a single producer/single consumer ring buffer.
 * Only one thread may write to this buffer at a time.
 * Only one thread may read from this buffer at a time.
 * One thread may write to this buffer at the same time as another thread reads
 * from this buffer.
 * This implementation does not contain any code to enforce the single producer/
 * single consumer policy.  That enforcement must be ensured by the application.
 * This works through the use of atomic pointers to the data in the buffer. */
typedef struct _oe_lockless_ring_buffer
{
    data_ptr write_pos;
    data_ptr read_pos;
    char* end_pos;
} oe_lockless_ring_buffer_t;

void oe_lockless_ring_buffer_init(
    oe_lockless_ring_buffer_t* buffer, size_t size);
oe_lockless_ring_buffer_t* oe_lockless_ring_buffer_alloc_and_init(size_t size);

size_t oe_lockless_ring_buffer_write(
    oe_lockless_ring_buffer_t* buffer, char* data, size_t size);

size_t oe_lockless_ring_buffer_read(
    oe_lockless_ring_buffer_t* buffer, char* data_out, size_t size);

OE_EXTERNC_END

#endif /* _LOCKLESS_RING_BUFFER_H_ */
