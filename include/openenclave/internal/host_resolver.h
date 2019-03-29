// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** host_resolver.h
**
**     Definition of the host_resolver internal types and data
**
**==============================================================================
*/

#ifndef _OE_HOST_RESOLVER_H__
#define _OE_HOST_RESOLVER_H__

#include <openenclave/internal/resolver.h>

OE_EXTERNC_BEGIN

oe_resolver_t* oe_get_hostresolver();

void oe_handle_hostresolver_ocall(void* args);

OE_EXTERNC_END

#endif /* _OE_HOST_RESOLVER_H */
