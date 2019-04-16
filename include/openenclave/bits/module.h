// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_MODULE_H
#define _OE_BITS_MODULE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t oe_load_module_hostfs(void);
oe_result_t oe_load_module_hostsock(void);
oe_result_t oe_load_module_hostresolver(void);
oe_result_t oe_load_module_polling(void);
oe_result_t oe_load_module_eventfd(void);

OE_EXTERNC_END

#endif /* _OE_BITS_MODULE_H */
