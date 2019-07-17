// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file module.h
 *
 * This file defines functions to load the optional modules available.
 *
 */
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

/**
 * Load the host file system module.
 *
 * This function loads the host file system module
 * which is needed for an enclave application to perform operations
 * such as mount, fopen, fread and fwrite on files located on the host.
 *
 * @retval OE_OK The module was successfully loaded.
 * @retval OE_FAILURE Module failed to load.
 *
 */
oe_result_t oe_load_module_host_file_system(void);

/**
 * Load the host socket interface module.
 *
 * This function loads the host socket interface module
 * which is needed for an enclave application to be able to call socket APIs
 * which are routed through the host.
 *
 * @retval OE_OK The module was successfully loaded.
 * @retval OE_FAILURE Module failed to load.
 *
 */
oe_result_t oe_load_module_host_socket_interface(void);

/**
 * Load the host resolver module.
 *
 * This function loads the host resolver module which is needed
 * for an enclave application to be able to call
 * getaddrinfo and getnameinfo.
 *
 * @retval OE_OK The module was successfully loaded.
 * @retval OE_FAILURE Module failed to load.
 */
oe_result_t oe_load_module_host_resolver(void);

/**
 * Load the event polling module epoll module.
 *
 * This function loads the host epoll module which is needed
 * for an enclave application to be able to call
 * epoll_create1, epoll_ctl, and epoll_wait
 *
 * @retval OE_OK The module was successfully loaded.
 * @retval OE_FAILURE Module failed to load.
 */
oe_result_t oe_load_module_host_epoll(void);
OE_EXTERNC_END

#endif /* _OE_BITS_MODULE_H */
