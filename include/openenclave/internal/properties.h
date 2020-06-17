// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_PROPERTIES_H
#define _OE_INTERNAL_PROPERTIES_H

#include <openenclave/bits/properties.h>

#if __x86_64__ || _M_X64
#include "sgx/sgxproperties.h"
#endif

#endif /* _OE_INTERNAL_PROPERTIES_H */
