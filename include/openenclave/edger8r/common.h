// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file common.h
 *
 * This file defines the inline functions, macros and data-structures used in
 * oeedger8r generated code on both enclave and host side.
 * These internals are subject to change without notice.
 *
 */
#ifndef _OE_EDGER8R_COMMON_H
#define _OE_EDGER8R_COMMON_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/******************************************************************************/
/********* Macros and inline functions used by generated code *****************/
/******************************************************************************/

/**
 * Each pointer/array parameter's sub-buffer in the input/output buffer will
 * be aligned to this value.
 * This alignment value must be consistent with alignment guarantees provided
 * by malloc - i.e aligned to store any standard C type.
 * In theory, this is the alignment that works for void* and the largest
 * types long long and long double.
 * 2* sizeof(void*) is the default value used by malloc libraries like dlmalloc.
 */

#define OE_EDGER8R_BUFFER_ALIGNMENT (2 * sizeof(void*))

/**
 * Add a size value, rounding to sizeof(void*).
 */
OE_INLINE oe_result_t oe_add_size(size_t* total, size_t size)
{
    oe_result_t result = OE_FAILURE;
    size_t align = OE_EDGER8R_BUFFER_ALIGNMENT;
    size_t sum = 0;

    // Round size to multiple of sizeof(void*)
    size_t rsize = ((size + align - 1) / align) * align;
    if (rsize < size)
    {
        result = OE_INTEGER_OVERFLOW;
        goto done;
    }

    // Add rounded-size and check for overflow.
    sum = *total + rsize;
    if (sum < *total)
    {
        result = OE_INTEGER_OVERFLOW;
        goto done;
    }

    *total = sum;
    result = OE_OK;

done:
    return result;
}

#define OE_ADD_SIZE(total, size)                                   \
    do                                                             \
    {                                                              \
        if (sizeof(total) > sizeof(size_t) && total > OE_SIZE_MAX) \
        {                                                          \
            _result = OE_INVALID_PARAMETER;                        \
            goto done;                                             \
        }                                                          \
        if (sizeof(size) > sizeof(size_t) && size > OE_SIZE_MAX)   \
        {                                                          \
            _result = OE_INVALID_PARAMETER;                        \
            goto done;                                             \
        }                                                          \
        if (oe_add_size((size_t*)&total, (size_t)size) != OE_OK)   \
        {                                                          \
            _result = OE_INTEGER_OVERFLOW;                         \
            goto done;                                             \
        }                                                          \
    } while (0)

/**
 * Compute and set the pointer value for the given parameter within the input
 * buffer. Make sure that the buffer has enough space.
 */
#define OE_SET_IN_POINTER(argname, argsize, argtype)                       \
    if (pargs_in->argname)                                                 \
    {                                                                      \
        pargs_in->argname = (argtype)(input_buffer + input_buffer_offset); \
        OE_ADD_SIZE(input_buffer_offset, (size_t)(argsize));               \
        if (input_buffer_offset > input_buffer_size)                       \
        {                                                                  \
            _result = OE_BUFFER_TOO_SMALL;                                 \
            goto done;                                                     \
        }                                                                  \
    }

#define OE_SET_IN_OUT_POINTER OE_SET_IN_POINTER

/**
 * Compute and set the pointer value for the given parameter within the output
 * buffer. Make sure that the buffer has enough space.
 */
#define OE_SET_OUT_POINTER(argname, argsize, argtype)                        \
    do                                                                       \
    {                                                                        \
        pargs_in->argname = (argtype)(output_buffer + output_buffer_offset); \
        OE_ADD_SIZE(output_buffer_offset, (size_t)(argsize));                \
        if (output_buffer_offset > output_buffer_size)                       \
        {                                                                    \
            _result = OE_BUFFER_TOO_SMALL;                                   \
            goto done;                                                       \
        }                                                                    \
    } while (0)

/**
 * Compute and set the pointer value for the given parameter within the output
 * buffer. Make sure that the buffer has enough space.
 * Also copy the contents of the corresponding in-out pointer in the input
 * buffer.
 */
#define OE_COPY_AND_SET_IN_OUT_POINTER(argname, argsize, argtype)            \
    if (pargs_in->argname)                                                   \
    {                                                                        \
        argtype _p_in = (argtype)pargs_in->argname;                          \
        pargs_in->argname = (argtype)(output_buffer + output_buffer_offset); \
        OE_ADD_SIZE(output_buffer_offset, (size_t)argsize);                  \
        if (output_buffer_offset > output_buffer_size)                       \
        {                                                                    \
            _result = OE_BUFFER_TOO_SMALL;                                   \
            goto done;                                                       \
        }                                                                    \
        memcpy(pargs_in->argname, _p_in, (size_t)(argsize));                 \
    }

/**
 * Copy an input parameter to input buffer.
 */
#define OE_WRITE_IN_PARAM(argname, argsize, argtype)                     \
    if (argname)                                                         \
    {                                                                    \
        _args.argname = (argtype)(_input_buffer + _input_buffer_offset); \
        OE_ADD_SIZE(_input_buffer_offset, (size_t)(argsize));            \
        memcpy((void*)_args.argname, argname, (size_t)(argsize));        \
    }

#define OE_WRITE_IN_OUT_PARAM OE_WRITE_IN_PARAM

/**
 * Read an output parameter from output buffer.
 */
#define OE_READ_OUT_PARAM(argname, argsize)                    \
    if (argname)                                               \
    {                                                          \
        memcpy(                                                \
            (void*)argname,                                    \
            _output_buffer + _output_buffer_offset,            \
            (size_t)(argsize));                                \
        OE_ADD_SIZE(_output_buffer_offset, (size_t)(argsize)); \
    }

#define OE_READ_IN_OUT_PARAM OE_READ_OUT_PARAM

/**
 * Check that a string is null terminated.
 */
#define OE_CHECK_NULL_TERMINATOR(str, size)                  \
    {                                                        \
        const char* _str = (const char*)(str);               \
        size_t _size = (size_t)(size);                       \
        if (_str && (_size == 0 || _str[_size - 1] != '\0')) \
        {                                                    \
            _result = OE_INVALID_PARAMETER;                  \
            goto done;                                       \
        }                                                    \
    }

/**
 * Check that a wstring is null terminated.
 */
#define OE_CHECK_NULL_TERMINATOR_WIDE(str, size)              \
    {                                                         \
        const wchar_t* _str = (const wchar_t*)(str);          \
        size_t _size = (size_t)(size);                        \
        if (_str && (_size == 0 || _str[_size - 1] != L'\0')) \
        {                                                     \
            _result = OE_INVALID_PARAMETER;                   \
            goto done;                                        \
        }                                                     \
    }

OE_EXTERNC_END

#endif // _OE_EDGER8R_COMMON_H
