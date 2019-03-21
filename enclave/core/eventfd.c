// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/internal/utils.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/eventfd.h>

int oe_eventfd(unsigned int initval, int flags)
{
    int ed = -1;
    oe_device_t* peventfd = NULL;
    oe_device_t* pdevice = NULL;

    pdevice = oe_get_devid_device(OE_DEVID_EVENTFD);
    if ((peventfd = (*pdevice->ops.eventfd->eventfd)(
             pdevice, (uint64_t)initval, flags)) == NULL)
    {
        return -1;
    }
    ed = oe_assign_fd_device(peventfd);
    if (ed == -1)
    {
        // ATTN: release peventfd here.
        // Log error here
        return -1; // erno is already set
    }

    return ed;
}

int oe_eventfd_read(int fd, oe_eventfd_t* value)
{
    return (int)oe_read(fd, value, sizeof(uint64_t));
}

int oe_eventfd_write(int fd, oe_eventfd_t value)
{
    return (int)oe_write(fd, &value, sizeof(uint64_t));
}

int oe_register_eventfd_device(void)
{
    int ret = -1;
    const uint64_t devid = OE_DEVID_EVENTFD;

    /* Allocate the device id. */
    if (oe_allocate_devid(devid) != devid)
        goto done;

    /* Add the hostfs device to the device table. */
    if (oe_set_devid_device(devid, oe_get_eventfd_device()) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}
