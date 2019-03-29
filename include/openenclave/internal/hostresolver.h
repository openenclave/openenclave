// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOSTRESOLVER_H
#define _OE_HOSTRESOLVER_H

#include <openenclave/internal/resolver.h>

OE_EXTERNC_BEGIN

oe_resolver_t* oe_get_hostresolver(void);

void oe_handle_hostresolver_ocall(void* args);

OE_EXTERNC_END

#endif /* _OE_HOSTRESOLVER_H */
