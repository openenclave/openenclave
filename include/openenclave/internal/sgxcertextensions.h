// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXCERTEXTENSIONS_H
#define _OE_SGXCERTEXTENSIONS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>

OE_EXTERNC_BEGIN

typedef struct _parsed_extension_info
{
    uint8_t ppid[16];
    uint8_t comp_svn[16];
    uint16_t pce_svn;
    uint8_t cpu_svn[16];
    uint8_t pce_id[2];
    uint8_t fmspc[6];
    uint8_t sgx_type;
    uint8_t opt_platform_instance_id[16];
    bool opt_dynamic_platform;
    bool opt_cached_keys;
    bool opt_smt_enabled;
} ParsedExtensionInfo;

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    size_t* buffer_size,
    ParsedExtensionInfo* parsed_info);

OE_EXTERNC_END

#endif // _OE_SGXCERTEXTENSIONS_H
