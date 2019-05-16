// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_MODULE_H
#define _OE_BITS_MODULE_H

/*
**==============================================================================
**
** This file defines functions for loading internal modules that are part of
** the Open Enclave core.
**
**==============================================================================
*/

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Load the host file system module. */
oe_result_t oe_load_module_host_file_system(void);

/* Load the host socket module. */
oe_result_t oe_load_module_host_socket_interface(void);

/* Load the host resolver module. */
oe_result_t oe_load_module_host_resolver(void);

/* Load the event polling module. */
oe_result_t oe_load_module_host_epoll(void);

/* Load the eventfd module. */
oe_result_t oe_load_module_eventfd(void);

OE_EXTERNC_END

#endif /* _OE_BITS_MODULE_H */
