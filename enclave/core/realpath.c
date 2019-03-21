// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>

char* oe_realpath(const char* path, char resolved_path[OE_PATH_MAX])
{
    char buf[OE_PATH_MAX];
    const char* in[OE_PATH_MAX];
    size_t nin = 0;
    const char* out[OE_PATH_MAX];
    size_t nout = 0;
    char resolved[OE_PATH_MAX];

    if (!path)
    {
        oe_errno = EINVAL;
        return NULL;
    }

    if (path[0] == '/')
    {
        if (oe_strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
        {
            oe_errno = ENAMETOOLONG;
            return NULL;
        }
    }
    else
    {
        char cwd[OE_PATH_MAX];

        if (!oe_getcwd(cwd, sizeof(cwd)))
            return NULL;

        if (oe_strlcpy(buf, cwd, sizeof(buf)) >= sizeof(buf))
        {
            oe_errno = ENAMETOOLONG;
            return NULL;
        }

        if (oe_strlcat(buf, "/", sizeof(buf)) >= sizeof(buf))
        {
            oe_errno = ENAMETOOLONG;
            return NULL;
        }

        if (oe_strlcat(buf, path, sizeof(buf)) >= sizeof(buf))
        {
            oe_errno = ENAMETOOLONG;
            return NULL;
        }
    }

    /* Split the path into elements. */
    {
        char* p;
        char* save;

        in[nin++] = "/";

        for (p = oe_strtok_r(buf, "/", &save); p;
             p = oe_strtok_r(NULL, "/", &save))
            in[nin++] = p;
    }

#if 0
for (size_t i = 0; i < nin; i++)
{
    oe_printf("in{%s}\n", in[i]);
}
#endif

    /* Normalize the path. */
    for (size_t i = 0; i < nin; i++)
    {
        /* Skip "." elements. */
        if (oe_strcmp(in[i], ".") == 0)
            continue;

        /* If "..", remove previous element. */
        if (oe_strcmp(in[i], "..") == 0)
        {
            if (nout > 1)
                nout--;
            continue;
        }

        out[nout++] = in[i];
    }

#if 0
for (size_t i = 0; i < nout; i++)
{
    oe_printf("out{%s}\n", out[i]);
}
#endif

    /* Build the resolved path. */
    {
        *resolved = '\0';

        for (size_t i = 0; i < nout; i++)
        {
            if (oe_strlcat(resolved, out[i], OE_PATH_MAX) >= OE_PATH_MAX)
            {
                oe_errno = ENAMETOOLONG;
                return NULL;
            }

            if (i != 0 && i + 1 != nout)
            {
                if (oe_strlcat(resolved, "/", OE_PATH_MAX) >= OE_PATH_MAX)
                {
                    oe_errno = ENAMETOOLONG;
                    return NULL;
                }
            }
        }
    }

    if (resolved_path)
    {
        if (oe_strlcpy(resolved_path, resolved, OE_PATH_MAX) >= OE_PATH_MAX)
        {
            oe_errno = ENAMETOOLONG;
            return NULL;
        }

        return resolved_path;
    }
    else
    {
        char* p = oe_strdup(resolved);

        if (!p)
            oe_errno = ENOMEM;

        return p;
    }

    return NULL;
}
