// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/argv.h>
#include <openenclave/internal/raise.h>

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/corelibc/string.h>
#define strlen oe_strlen
#else
#include <string.h>
#endif

#define MAX_LENGTHS 32

oe_result_t oe_argv_to_buffer(
    const char* argv[],
    size_t argc,
    void* buf_out,
    size_t buf_size,
    size_t* buf_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t required_size = 0;
    size_t i;
    size_t lengths[MAX_LENGTHS];

    if (!argv || !buf_size_out)
        goto done;

    /* Handle empty argv list case up front. */
    if (argc == 0)
    {
        *buf_size_out = 0;
        result = OE_OK;
        goto done;
    }

    /* Determine the total memory requirements. */
    for (i = 0; i < argc; i++)
    {
        size_t len;

        if (!argv[i])
            OE_RAISE(OE_FAILURE);

        len = strlen(argv[i]);

        if (i < MAX_LENGTHS)
            lengths[i] = len;

        required_size += len + 1;
    }

    /* Fail if the buffer is too small. */
    if (buf_size < required_size)
    {
        *buf_size_out = required_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy the strings onto the allocated buffer. */
    if (buf_out)
    {
        char* p = (char*)buf_out;

        for (i = 0; i < argc; i++)
        {
            size_t len = (i < MAX_LENGTHS) ? lengths[i] : strlen(argv[i]);
            memcpy(p, argv[i], len + 1);
            p += len + 1;
        }
    }

    *buf_size_out = required_size;
    result = OE_OK;

done:

    return result;
}

oe_result_t oe_buffer_to_argv(
    const void* buf,
    size_t buf_size,
    char*** argv_out,
    size_t argc,
    void* (*malloc_func)(size_t),
    void (*free_func)(void*))
{
    oe_result_t result = OE_UNEXPECTED;
    char** argv = NULL;
    size_t argv_size;
    size_t alloc_size = 0;
    size_t index = 0;

    if (!buf || !argv_out || !malloc_func || !free_func)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Calculate the total size of argv. */
    {
        const char* p = (const char*)buf;
        const char* end = (const char*)buf + buf_size;

        /* Leave room for null argv[argc] entry. */
        argv_size = sizeof(char*) * (argc + 1);
        alloc_size += argv_size;

        while (p != end)
        {
            const char* start = p;

            while (*p && p != end)
                p++;

            if (*p != '\0')
                OE_RAISE(OE_FAILURE);

            p++;
            alloc_size += (size_t)(p - start);
        }

        if (p != end)
            OE_RAISE(OE_FAILURE);
    }

    /* Allocate the argv memory. */
    if (!(argv = (*malloc_func)(alloc_size)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Copy the strings onto the argv memory. */
    {
        const char* p = (char*)buf;
        const char* end = (char*)buf + buf_size;
        char* q = (char*)argv + argv_size;

        while (p != end)
        {
            const char* start = p;

            if (index == argc)
                OE_RAISE(OE_FAILURE);

            while (*p && p != end)
                p++;

            p++;

            argv[index++] = q;
            memcpy(q, start, (size_t)(p - start));
            q += p - start;
        }

        argv[index] = NULL;
    }

    /* Check that the correct number of strings were extracted. */
    if (index != argc)
        OE_RAISE(OE_FAILURE);

    *argv_out = argv;
    argv = NULL;
    result = OE_OK;

done:

    if (argv)
        (*free_func)(argv);

    return result;
}
