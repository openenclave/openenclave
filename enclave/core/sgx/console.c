// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/hostfs.h>
#include <openenclave/internal/print.h>

int oe_initialize_console_devices(void)
{
    int ret = -1;
    oe_device_t* hostfs;
    oe_device_t* in = NULL;
    oe_device_t* out = NULL;
    oe_device_t* err = NULL;

    /* Get the hostfs singleton instance. */
    if (!(hostfs = oe_fs_get_hostfs()))
        goto done;

    /* Open stdin. */
    if (!(in = hostfs->ops.fs->open(hostfs, "/dev/stdin", OE_O_RDONLY, 0)))
        goto done;

    /* Open stdout. */
    if (!(out = hostfs->ops.fs->open(hostfs, "/dev/stdout", OE_O_WRONLY, 0)))
        goto done;

    /* Open stderr. */
    if (!(err = hostfs->ops.fs->open(hostfs, "/dev/stderr", OE_O_WRONLY, 0)))
        goto done;

    /* Set the stdin device. */
    if (!oe_set_fd_device(OE_STDIN_FILENO, in))
        goto done;

    /* Set the stdout device. */
    if (!oe_set_fd_device(OE_STDOUT_FILENO, out))
        goto done;

    /* Set the stderr device. */
    if (!oe_set_fd_device(OE_STDERR_FILENO, err))
        goto done;

    in = NULL;
    out = NULL;
    err = NULL;
    ret = 0;

done:

    if (in)
        in->ops.base->close(in);

    if (out)
        out->ops.base->close(out);

    if (err)
        err->ops.base->close(err);

    return ret;
}
