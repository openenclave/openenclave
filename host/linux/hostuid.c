// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/host.h>
#include <unistd.h>
#include <openenclave/internal/posix/uid.h>
// clang-format on

pid_t oe_get_host_pid(void)
{
    return (pid_t)getpid();
}

pid_t oe_get_host_ppid(void)

{
    return (pid_t)getppid();
}

pid_t oe_get_host_pgrp(void)
{
    return (pid_t)getpgrp();
}

uid_t oe_get_host_uid(void)
{
    return (uid_t)getuid();
}

uid_t oe_get_host_euid(void)
{
    return (uid_t)geteuid();
}

int32_t oe_get_host_groups(size_t size, gid_t plist[])
{
    int32_t retval = -1;
    gid_t list[OE_NGROUP_MAX] = {0};
    int idx = 0;

    if (size > OE_NGROUP_MAX)
    {
        size = OE_NGROUP_MAX;
    }

    retval = getgroups((int)size, list);
    if (retval > 0)
    {
        // We track gids as uint64_t because they could be windows handles.
        // getgroups returns a list of uint32_t. So we need to convert
        for (idx = 0; idx < (int)size; idx++)
        {
            plist[idx] = (gid_t)list[idx];
        }
    }

    return retval;
}
