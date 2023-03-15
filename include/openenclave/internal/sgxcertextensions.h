// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXCERTEXTENSIONS_H
#define _OE_SGXCERTEXTENSIONS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>

OE_EXTERNC_BEGIN

typedef struct _oe_parsed_extension_info
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
} oe_parsed_extension_info_t;

oe_result_t oe_parse_sgx_extensions(
    oe_cert_t* cert,
    oe_parsed_extension_info_t* parsed_info);

OE_EXTERNC_END

#endif // _OE_SGXCERTEXTENSIONS_H
