// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/host.h>
#include <unistd.h>
#include <openenclave/internal/uid.h>
// clang-format on

oe_pid_t oe_get_host_pid(void)

{
    return (oe_pid_t)getpid();
}

oe_pid_t oe_get_host_ppid(void)

{
    return (oe_pid_t)getppid();
}

oe_pid_t oe_get_host_pgrp(void)

{
    return (oe_pid_t)getpgrp();
}

oe_pid_t oe_get_host_uid(void)

{
    return (oe_pid_t)getuid();
}

oe_pid_t oe_get_host_euid(void)

{
    return (oe_pid_t)geteuid();
}

int32_t oe_get_host_groups(size_t size, oe_gid_t plist[])

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
            plist[idx] = (oe_gid_t)list[idx];
        }
    }

    return retval;
}
