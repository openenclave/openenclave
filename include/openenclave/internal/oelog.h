// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OELOG_H
#define _OELOG_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

// logging flags
#define OE_LOG_FLAGS_ATTESTATION    0x00000001
#define OE_LOG_FLAGS_GET_REPORT     0x00000002
#define OE_LOG_FLAGS_VERIFY_REPORT  0x00000004
#define OE_LOG_FLAGS_COMMON         0x00000008
#define OE_LOG_FLAGS_CERT           0x00000010
#define OE_LOG_FLAGS_TOOLS          0x00000020
#define OE_LOG_FLAGS_CRYPTO         0x00000040
#define OE_LOG_FLAGS_SGX_SPECIFIC   0x00000100
#define OE_LOG_FLAGS_IMAGE_LOADING  0x00000200
#define OE_LOG_FLAGS_ALL            0xffffffff

typedef enum LogLevel
{
  OE_LOG_NONE = 0, 
  OE_LOG_DEBUG, 
  OE_LOG_INFO, 
  OE_LOG_WARN, 
  OE_LOG_ERROR 
} log_level_t;

/* Maximum log length */
#define OE_LOG_MESSAGE_LEN_MAX 256

typedef struct _oe_log_filter
{
  uint64_t modules;
  log_level_t level;
} oe_log_filter_t;

typedef struct _oe_log_args
{
  uint64_t module;
  log_level_t level;
  char message[OE_LOG_MESSAGE_LEN_MAX];
} oe_log_args_t;

OE_EXTERNC_END

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>

OE_EXTERNC_BEGIN

oe_result_t oe_log(uint64_t module, log_level_t level, const char* fmt, ...);

OE_EXTERNC_END
#else
#include <stdio.h>

OE_EXTERNC_BEGIN

int oe_log_host_init(const char *path, uint64_t modules, log_level_t level);
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave, uint64_t modules, log_level_t level);
void oe_log(uint64_t module, log_level_t level, const char* fmt, ...);
void oe_log_close(void);

OE_EXTERNC_END

#endif

#endif /* _OELOG_H */
