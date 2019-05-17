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
#include <openenclave/corelibc/sys/eventfd.h>
#include <openenclave/internal/posix/fdtable.h>
#include <openenclave/internal/posix/device.h>
#include <openenclave/internal/posix/raise.h>

int oe_eventfd(unsigned int initval, int flags)
{
    int ret = -1;
    int ed;
    oe_device_t* device;
    oe_fd_t* eventfd = NULL;

    if (!(device = oe_get_device(OE_DEVID_EVENTFD, OE_DEVICE_TYPE_EVENTFD)))
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(eventfd = device->ops.eventfd.eventfd(device, initval, flags)))
        OE_RAISE_ERRNO(oe_errno);

    if ((ed = oe_fdtable_assign(eventfd)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    ret = ed;
    eventfd = NULL;

done:

    if (eventfd)
        return eventfd->ops.fd.close(eventfd);

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
