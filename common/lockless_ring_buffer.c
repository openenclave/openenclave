/* Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. */

#include <openenclave/bits/lockless_ring_buffer.h>
//#include <stdlib.h>
#include <string.h>


// including stdlib.h lets this build on the host

//#ifdef OE_BUILD_ENCLAVE
//#include <stdlib.h>
//#else
//#include <stdlib.h>
//#endif /* _MSC_VER */

#ifdef _MSC_VER
#include <intrin.h>
#endif /* _MSC_VER */

static size_t _min(size_t a, size_t b)
{
    return (a < b) ? a : b;
} /* _min */

/* _get_read_pos uses acquire semantics.
 * Because all of the variables in the ring buffer are atomic and because this
 * uses acquire semantics all of the ring buffer variables for this thread's
 * cache are updated from memory when this method is called. */
static char* _get_read_pos(oe_lockless_ring_buffer_t* buffer)
{
    char* read_pos = NULL;
#ifdef _MSC_VER
    read_pos = (char*)_InterlockedCompareExchangePointer(
        &(buffer->read_pos), NULL, NULL);
#elif defined __GNUC__
    read_pos = __atomic_load_n(&(buffer->read_pos), __ATOMIC_ACQUIRE);
#endif /*_MSC_VER or __GNUC__ */
    return read_pos;
} /* _get_read_pos */

#if (1)
/* _get_write_pos uses acquire semantics.
 * Because all of the variables in the ring buffer are atomic and because this
 * uses acquire semantics all of the ring buffer variables for this thread's
 * cache are updated from memory when this method is called. */
static char* _get_write_pos(oe_lockless_ring_buffer_t* buffer)
{
    char* write_pos = NULL;
#ifdef _MSC_VER
    write_pos = (char*)_InterlockedCompareExchangePointer(
        &(buffer->write_pos), NULL, NULL);
#elif defined __GNUC__
    write_pos = __atomic_load_n(&(buffer->write_pos), __ATOMIC_ACQUIRE);
#endif /*_MSC_VER or __GNUC__ */
    return write_pos;
} /* _get_write_pos */
#endif

#if (1)
/* set_read_pos uses release semantics
 * Because all of the variables in the ring buffer are atomic and because this
 * uses release semantics all of the ring buffer variables in the current
 * thread's cache are written to memory when this method is called. */
static void _set_read_pos(oe_lockless_ring_buffer_t* buffer, char* read_pos)
{
#ifdef _MSC_VER
    _InterlockedExchangePointer(&(buffer->read_pos), read_pos);
#elif defined __GNUC__
    __atomic_store_n(&(buffer->read_pos), read_pos, __ATOMIC_RELEASE);
#endif /*_MSC_VER or __GNUC__ */
} /* _set_read_pos */
#endif

/* set_write_pos uses release semantics
 * Because all of the variables in the ring buffer are atomic and because this
 * uses release semantics all of the ring buffer variables in the current
 * thread's cache are written to memory when this method is called. */
static void _set_write_pos(oe_lockless_ring_buffer_t* buffer, char* write_pos)
{
#ifdef _MSC_VER
    _InterlockedExchangePointer(&(buffer->write_pos), write_pos);
#elif defined __GNUC__
    __atomic_store_n(&(buffer->write_pos), write_pos, __ATOMIC_RELEASE);
#endif /*_MSC_VER or __GNUC__ */
} /* _set_write_pos */

static char* _get_offset_to_data(oe_lockless_ring_buffer_t* buffer)
{
    return (char*)buffer + sizeof(oe_lockless_ring_buffer_t);
} /* _get_offset_to_data */

void oe_lockless_ring_buffer_init(
    oe_lockless_ring_buffer_t* buffer,
    size_t size)
{
    buffer->write_pos = buffer->read_pos = _get_offset_to_data(buffer);
    buffer->end_pos = buffer->read_pos + size;
} /* oe_lockless_ring_buffer_init */

#if (0)
oe_lockless_ring_buffer_t* oe_lockless_ring_buffer_alloc_and_init(size_t size)
{
    oe_lockless_ring_buffer_t* buffer = (oe_lockless_ring_buffer_t*)malloc(
        size + sizeof(oe_lockless_ring_buffer_t));
    if (NULL != buffer)
    {
        oe_lockless_ring_buffer_init(buffer, size);
    }
    return buffer;
} /* oe_lockless_ring_buffer_alloc_and_init */
#endif

/* Only one thread is allowed to write at a time.
 * It is safe to assume that write_pos will not be changed by another thread
 * during this call.
 * This function is the only place where write_pos is updated.
 * This function calls _set_write_pos before it exits which updates the
 * variables in memory.
 * The method starts with a call to _get_read_pos which forces an update of
 * all thread cache variables because it uses acquire semantics. */
size_t oe_lockless_ring_buffer_write(
    oe_lockless_ring_buffer_t* buffer, char* data, size_t size)
{
    size_t written = 0;
    char* read_pos = _get_read_pos (buffer);
    char* write_pos = buffer->write_pos;

    /* if write_pos is >= read_pos then write to end_pos */
    if (write_pos >= read_pos)
    {
        /* if is safe to write to the memory between write_pos and end_pos */
        written = _min((size_t)(buffer->end_pos - write_pos), size);
        memcpy(write_pos, data, written);
        write_pos += written;
    }

    /* if write_pos is end_pos and read_pos is not _get_offset_to_data then
     * move write_pos to _get_offset_to_data */
    if (write_pos == buffer->end_pos && read_pos != _get_offset_to_data(buffer))
    {
        write_pos = _get_offset_to_data(buffer);
    }

    /* if written < size and (write_pos + 1) < read_pos */
    if (written < size && (write_pos + 1) < read_pos)
    {
        /* it is safe to write to the memory between write_pos and
         * read_pos - 1 */
        size_t additional_written =
            _min((size_t)((read_pos - 1) - write_pos), size - written);
        memcpy(write_pos, data + written, additional_written);
        write_pos += additional_written;
        written += additional_written;
    }

    /* if anything was written then update write_pos */
    if (0 < written)
    {
        _set_write_pos(buffer, write_pos);
    }

    return written;
} /* oe_lockless_ring_buffer_write */


size_t oe_lockless_ring_buffer_read(
    oe_lockless_ring_buffer_t* buffer, char* data_out, size_t size)
{
    size_t read = 0;
    char* write_pos = _get_write_pos(buffer);
    char* read_pos = buffer->read_pos;

    /* if read_pos > write_pos then read to end_pos */
    if (read_pos > write_pos &&
        read_pos < buffer->end_pos)
    {
        read = _min((size_t)(buffer->end_pos - read_pos), size);
        memcpy(data_out, read_pos, read);
        read_pos += read;
    }

    /* if read_pos is end_pos and write_pos is not end_pos then move read_pos to
     * _get_offset_to_data */
    if (read_pos == buffer->end_pos && write_pos != buffer->end_pos)
    {
        read_pos = _get_offset_to_data(buffer);
    }

    /* if size > read and read_pos is < write_pos */
    if (size > read && read_pos < write_pos)
    {
        /* it is safe to read from read_pos to write_pos */
        size_t additional_read =
            _min ((size_t)(write_pos - read_pos), size - read);
        memcpy(data_out + read, read_pos, additional_read);
        read_pos += additional_read;
        read += additional_read;
    }

    /* is anything was read then update read_pos */
    if (0 < read)
    {
        _set_read_pos(buffer, read_pos);
    }

    return read;
}
