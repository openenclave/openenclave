/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _LIBCEX_COMMON_H
#define _LIBCEX_COMMON_H

#define OE_FILE_INSECURE OE_DEVID_HOSTFS
#define OE_FILE_SECURE_HARDWARE OE_DEVID_SHWFS
#define OE_FILE_SECURE_ENCRYPTION OE_DEVID_SGXFS

#ifdef OE_USE_OPTEE
#define OE_FILE_SECURE_BEST_EFFORT OE_FILE_SECURE_HARDWARE
#else
#define OE_FILE_SECURE_BEST_EFFORT OE_FILE_SECURE_ENCRYPTION
#endif

#endif /* _LIBCEX_COMMON_H */
