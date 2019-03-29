// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/epoll.h>
#include <openenclave/internal/eventfd.h>
#include <openenclave/internal/hostfs.h>
#include <openenclave/internal/hostresolver.h>
#include <openenclave/internal/hostsock.h>

static bool _enabled[__OE_FEATURE_MAX];

oe_result_t oe_enable_feature(oe_feature_t feature)
{
    oe_result_t result = OE_UNEXPECTED;

    if (_enabled[feature])
    {
        result = OE_OK;
        goto done;
    }

    switch (feature)
    {
        case OE_FEATURE_HOST_FILES:
        {
            if (oe_register_hostfs_device() != 0)
            {
                result = OE_FAILURE;
                goto done;
            }

            break;
        }
        case OE_FEATURE_HOST_SOCKETS:
        {
            if (oe_register_hostsock_device() != 0)
            {
                result = OE_FAILURE;
                goto done;
            }

            break;
        }
        case OE_FEATURE_POLLING:
        {
            if (oe_register_epoll_device() != 0)
            {
                result = OE_FAILURE;
                goto done;
            }

            if (oe_register_eventfd_device() != 0)
            {
                result = OE_FAILURE;
                goto done;
            }

            break;
        }
        case OE_FEATURE_HOST_RESOLVER:
        {
            oe_resolver_t* resolver = oe_get_hostresolver();

            if (!resolver)
            {
                result = OE_FAILURE;
                goto done;
            }

            if (oe_register_resolver(2, resolver) != 0)
            {
                result = OE_FAILURE;
                goto done;
            }

            break;
        }
        default:
        {
            goto done;
        }
    }

    _enabled[feature] = true;
    result = OE_OK;

done:
    return result;
}
