// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
// clang-format on

#include <openenclave/internal/thread.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/trace.h>
#include "include/eventfd.h"
#include "include/fd.h"

int oe_eventfd(unsigned int initval, int flags)
{
    int ret = -1;
    int ed;
    oe_device_t* device;
    oe_device_t* eventfd = NULL;

    if (!(device = oe_get_device(OE_DEVID_EVENTFD, OE_DEVICE_TYPE_EVENTFD)))
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d\n", oe_errno);
        goto done;
    }

    if (!(eventfd = (*device->ops.eventfd->eventfd)(device, initval, flags)))
    {
        OE_TRACE_ERROR("oe_errno=%d\n", oe_errno);
        goto done;
    }

    if ((ed = oe_assign_fd_device(eventfd)) == -1)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d\n", oe_errno);
        goto done;
    }

    ret = ed;
    eventfd = NULL;

done:

    if (eventfd)
    {
        // ATTN: release this device.
    }

    return ret;
}

int oe_eventfd_read(int fd, oe_eventfd_t* value)
{
    if (oe_read(fd, value, sizeof(uint64_t)) != sizeof(uint64_t))
        return -1;

    return 0;
}

int oe_eventfd_write(int fd, oe_eventfd_t value)
{
    if (oe_write(fd, &value, sizeof(uint64_t)) != sizeof(uint64_t))
        return -1;

    return 0;
}
