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

/*
 * Note that we cannot directly use OE_ADD_ARG_SIZE to calculate the
 * size because OE_ADD_SIZE enforces the alignment on the addend.
 */
#define OE_COMPUTE_ARG_SIZE(total, argcount, argsize)                      \
    do                                                                     \
    {                                                                      \
        size_t _argcount = (size_t)(argcount);                             \
        size_t _argsize = (size_t)(argsize);                               \
        if (_argcount && _argsize && (_argcount > OE_SIZE_MAX / _argsize)) \
        {                                                                  \
            _result = OE_INTEGER_OVERFLOW;                                 \
            goto done;                                                     \
        }                                                                  \
        total = _argcount * _argsize;                                      \
    } while (0)

#define OE_ADD_ARG_SIZE(total, argcount, argsize)               \
    do                                                          \
    {                                                           \
        size_t _total_argsize = 0;                              \
        OE_COMPUTE_ARG_SIZE(_total_argsize, argcount, argsize); \
        OE_ADD_SIZE(total, _total_argsize);                     \
    } while (0);

/**
 * Compute and set the pointer value for the given parameter within the input
 * buffer. Make sure that the buffer has enough space.
 */
#define OE_SET_IN_POINTER(argname, argcount, argsize, argtype)               \
    if (_pargs_in->argname)                                                  \
    {                                                                        \
        _pargs_in->argname = (argtype)(input_buffer + _input_buffer_offset); \
        OE_ADD_ARG_SIZE(_input_buffer_offset, argcount, argsize);            \
        if (_input_buffer_offset > input_buffer_size)                        \
        {                                                                    \
            _result = OE_BUFFER_TOO_SMALL;                                   \
            goto done;                                                       \
        }                                                                    \
    }

#define OE_SET_IN_OUT_POINTER OE_SET_IN_POINTER

/**
 * Compute and set the pointer value for the given parameter within the output
 * buffer. Make sure that the buffer has enough space.
 */
#define OE_SET_OUT_POINTER(argname, argcount, argsize, argtype)                \
    do                                                                         \
    {                                                                          \
        _pargs_in->argname = (argtype)(output_buffer + _output_buffer_offset); \
        OE_ADD_ARG_SIZE(_output_buffer_offset, argcount, argsize);             \
        if (_output_buffer_offset > output_buffer_size)                        \
        {                                                                      \
            _result = OE_BUFFER_TOO_SMALL;                                     \
            goto done;                                                         \
        }                                                                      \
    } while (0)

/**
 * Compute and set the pointer value for the given parameter within the output
 * buffer. Make sure that the buffer has enough space.
 * Also copy the contents of the corresponding in-out pointer in the input
 * buffer.
 */
#define OE_COPY_AND_SET_IN_OUT_POINTER(argname, argcount, argsize, argtype)    \
    if (_pargs_in->argname)                                                    \
    {                                                                          \
        size_t _size = 0;                                                      \
        OE_COMPUTE_ARG_SIZE(_size, argcount, argsize);                         \
        argtype _p_in = (argtype)_pargs_in->argname;                           \
        _pargs_in->argname = (argtype)(output_buffer + _output_buffer_offset); \
        OE_ADD_SIZE(_output_buffer_offset, _size);                             \
        if (_output_buffer_offset > output_buffer_size)                        \
        {                                                                      \
            _result = OE_BUFFER_TOO_SMALL;                                     \
            goto done;                                                         \
        }                                                                      \
        memcpy(_pargs_in->argname, _p_in, _size);                              \
    }

/**
 * Copy an input parameter to input buffer.
 */
#define OE_WRITE_IN_PARAM(argname, argcount, argsize, argtype)           \
    if (argname)                                                         \
    {                                                                    \
        size_t _size = 0;                                                \
        OE_COMPUTE_ARG_SIZE(_size, argcount, argsize);                   \
        _args.argname = (argtype)(_input_buffer + _input_buffer_offset); \
        OE_ADD_SIZE(_input_buffer_offset, _size);                        \
        memcpy((void*)_args.argname, argname, _size);                    \
    }

#define OE_WRITE_IN_OUT_PARAM OE_WRITE_IN_PARAM

#define OE_WRITE_DEEPCOPY_OUT_PARAM(argname, argcount, argsize)                \
    if (argname)                                                               \
    {                                                                          \
        size_t _size = 0;                                                      \
        OE_COMPUTE_ARG_SIZE(_size, argcount, argsize);                         \
        void* p = (void*)(_deepcopy_out_buffer + _deepcopy_out_buffer_offset); \
        OE_ADD_SIZE(_deepcopy_out_buffer_offset, _size);                       \
        memcpy(p, argname, _size);                                             \
    }

#define OE_SET_DEEPCOPY_OUT_PARAM(argname, argcount, argsize, argtype)     \
    if (argname)                                                           \
    {                                                                      \
        size_t _size = 0;                                                  \
        OE_COMPUTE_ARG_SIZE(_size, argcount, argsize);                     \
        argname = (argtype)malloc(_size);                                  \
        if (!argname)                                                      \
        {                                                                  \
            _result = OE_OUT_OF_MEMORY;                                    \
            goto done;                                                     \
        }                                                                  \
        argtype _ptr =                                                     \
            (argtype)(_deepcopy_out_buffer + _deepcopy_out_buffer_offset); \
        OE_ADD_SIZE(_deepcopy_out_buffer_offset, _size);                   \
        if (_deepcopy_out_buffer_offset > _deepcopy_out_buffer_size)       \
        {                                                                  \
            _result = OE_BUFFER_TOO_SMALL;                                 \
            goto done;                                                     \
        }                                                                  \
        memcpy(argname, _ptr, _size);                                      \
    }

/**
 * Read an output parameter from output buffer.
 */
#define OE_READ_OUT_PARAM(argname, argcount, argsize)                          \
    if (argname)                                                               \
    {                                                                          \
        size_t _size = 0;                                                      \
        OE_COMPUTE_ARG_SIZE(_size, argcount, argsize);                         \
        memcpy((void*)argname, _output_buffer + _output_buffer_offset, _size); \
        OE_ADD_SIZE(_output_buffer_offset, _size);                             \
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
