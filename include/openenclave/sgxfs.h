// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXFS_H
#define _OE_SGXFS_H

OE_EXTERNC_BEGIN

/**
 * Register the Intel SGX protected file system (SGXFS).
 *
 * The enclave calls this function to register the Intel SGX protected file
 * system (SGXFS). Afterwards, enclaves can use SGXFS by mounting the file
 * system. For example:
 *
 *
 * ```
 * #include <sys/mount.h>
 *
 * void example(void)
 * {
 *
 *     if (oe_load_module_sgxfs() != OE_OK)
 *     {
 *         // error!
 *     }
 *
 *     if (mount("/", "/", "sgxfs", 0, NULL) != 0)
 *     {
 *         // error!
 *     }
 *
 *     if (open("/tmp/somefile", O_WRONLY | O_CREAT, 0644) != 0)
 *     {
 *         // error!
 *     }
 * }
 *
 */
oe_result_t oe_load_module_sgxfs(void);

OE_EXTERNC_END

#endif /* _OE_SGXFS_H */
