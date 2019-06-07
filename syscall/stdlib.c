// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/trace.h>

char* oe_realpath(const char* path, oe_syscall_path_t* resolved_path)
{
    char* ret = NULL;
    typedef struct _variables
    {
        char buf[OE_PATH_MAX];
        const char* in[OE_PATH_MAX];
        const char* out[OE_PATH_MAX];
        char resolved[OE_PATH_MAX];
    } variables_t;
    variables_t* v = NULL;
    size_t nin = 0;
    size_t nout = 0;

    if (!path)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Allocate variables on the heap since too big for the stack. */
    if (!(v = oe_calloc(1, sizeof(variables_t))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    if (path[0] == '/')
    {
        if (oe_strlcpy(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);
    }
    else
    {
        char cwd[OE_PATH_MAX];

        if (!oe_getcwd(cwd, sizeof(cwd)))
            OE_RAISE_ERRNO(OE_EINVAL);

        if (oe_strlcpy(v->buf, cwd, sizeof(v->buf)) >= sizeof(v->buf))
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);

        if (oe_strlcat(v->buf, "/", sizeof(v->buf)) >= sizeof(v->buf))
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);

        if (oe_strlcat(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);
    }

    /* Split the path into elements. */
    {
        char* p;
        char* save;

        v->in[nin++] = "/";

        for (p = oe_strtok_r(v->buf, "/", &save); p;
             p = oe_strtok_r(NULL, "/", &save))
        {
            v->in[nin++] = p;
        }
    }

    /* Normalize the path. */
    for (size_t i = 0; i < nin; i++)
    {
        /* Skip "." elements. */
        if (oe_strcmp(v->in[i], ".") == 0)
            continue;

        /* If "..", remove previous element. */
        if (oe_strcmp(v->in[i], "..") == 0)
        {
            if (nout > 1)
                nout--;
            continue;
        }

        v->out[nout++] = v->in[i];
    }

    /* Build the resolved path. */
    {
        *v->resolved = '\0';

        for (size_t i = 0; i < nout; i++)
        {
            if (oe_strlcat(v->resolved, v->out[i], OE_PATH_MAX) >= OE_PATH_MAX)
                OE_RAISE_ERRNO(OE_ENAMETOOLONG);

            if (i != 0 && i + 1 != nout)
            {
                if (oe_strlcat(v->resolved, "/", OE_PATH_MAX) >= OE_PATH_MAX)
                    OE_RAISE_ERRNO(OE_ENAMETOOLONG);
            }
        }
    }

    if (resolved_path)
    {
        if (oe_strlcpy(resolved_path->buf, v->resolved, OE_PATH_MAX) >=
            OE_PATH_MAX)
            OE_RAISE_ERRNO(OE_ENAMETOOLONG);

        ret = resolved_path->buf;
        goto done;
    }
    else
    {
        char* p = oe_strdup(v->resolved);

        if (!p)
            OE_RAISE_ERRNO(OE_ENOMEM);

        ret = p;
        goto done;
    }

done:

    if (v)
        oe_free(v);

    return ret;
}

OE_NO_RETURN void oe_exit(int status)
{
    OE_UNUSED(status);

    oe_printf("oe_exit() panic");
    oe_abort();

    /* Never return. */
    for (;;)
        ;
}
