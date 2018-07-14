// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_GETOPT_H
#define _OE_GETOPT_H

#include <openenclave/host.h>
#include <string.h>

/**
 * Gets a command line option, removing that option and its optional argument
 * from argc-argv. A pointer to the option argument (if any) is stored in the
 * **arg** output parameter.
 *
 * @param argc[in,out] number of arguments.
 * @param argv[in,out] array of arguments.
 * @param name[in] name of the argument (e.g., "--someopt").
 * @param arg[out] pointer to the optional output argument if any (may be null).
 *
 * @return  1 the option was found.
 * @return  0 the option was not found.
 * @return -1 an error occurred (bad parameter or missing option argument).
 *
 */
OE_INLINE int oe_getopt(
    int* argc,
    const char* argv[],
    const char* name,
    const char** arg = NULL)
{
    if (!argc || !argv || !name)
        return -1;

    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (arg)
            {
                if (i + 1 == *argc)
                    return -1;

                *arg = argv[i + 1];
                const size_t n = (*argc - i - 1);
                memmove((char**)&argv[i], &argv[i + 2], n * sizeof(char*));
                *argc -= 2;
            }
            else
            {
                const size_t n = (*argc - i);
                memmove((void*)&argv[i], &argv[i + 1], n * sizeof(char*));
                (*argc)--;
            }

            return 1;
        }
    }

    return 0;
}

#endif /* _OE_GETOPT_H */
