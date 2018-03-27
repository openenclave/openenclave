// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_PEM_H
#define _OE_PEM_H

#include <openenclave/defs.h>

OE_EXTERNC_BEGIN

#define OE_PEM_BEGIN_CERTIFICATE "-----BEGIN CERTIFICATE-----"
#define OE_PEM_BEGIN_CERTIFICATE_LEN (sizeof(OE_PEM_BEGIN_CERTIFICATE) - 1)

#define OE_PEM_END_CERTIFICATE "-----END CERTIFICATE-----"
#define OE_PEM_END_CERTIFICATE_LEN (sizeof(OE_PEM_END_CERTIFICATE) - 1)

OE_EXTERNC_END

#endif /* _OE_PEM_H */
