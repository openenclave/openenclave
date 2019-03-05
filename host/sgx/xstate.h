// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_XSTATE_H
#define _OE_XSTATE_H

#include <openenclave/internal/sgxtypes.h>

/* Detect the XSave Feature Request Mask (XFRM) to set in the enclave */
uint64_t _xfrm_detect(void);

/* Read XCR0 register, which the OS programs to reflect the features for
 * which it provides context management.
 */
uint64_t oe_get_xfrm(void);

#endif /* _OE_XSTATE_H */
