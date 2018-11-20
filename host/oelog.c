// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include "enclave.h"
#include "hostthread.h"
#include "oelog.h"

static oe_mutex oe_log_lock = OE_H_MUTEX_INITIALIZER;
static FILE *LogFile = NULL;
static log_level_t LogLevel = OE_LOG_NONE;
static uint64_t LogModules = 0;

static const char* log_module(uint64_t module)
{
  switch (module) {
    case OE_LOG_FLAGS_ATTESTATION: return "FLAGS_ATTESTATION";
    case OE_LOG_FLAGS_GET_REPORT: return "FLAGS_GET_REPORT";
    case OE_LOG_FLAGS_VERIFY_REPORT: return "FLAGS_VERIFY_REPORT";
    case OE_LOG_FLAGS_COMMON: return "FLAGS_COMMON";
    case OE_LOG_FLAGS_CERT: return "FLAGS_CERT";
    case OE_LOG_FLAGS_TOOLS: return "FLAGS_TOOLS";
    case OE_LOG_FLAGS_CRYPTO: return "FLAGS_CRYPTO";
    case OE_LOG_FLAGS_SGX_SPECIFIC: return "FLAGS_SGX_SPECIFIC";
    case OE_LOG_FLAGS_IMAGE_LOADING: return "FLAGS_IMAGE_LOADING";
    case OE_LOG_FLAGS_ALL: return "FLAGS_ALL";
    default: return "N/A";
  }
}

static const char* log_level(log_level_t level)
{
  switch (level) {
    case OE_LOG_DEBUG: return "DEBUG";
    case OE_LOG_INFO: return "INFO";
    case OE_LOG_WARN: return "WARN";
    case OE_LOG_ERROR: return "ERROR";
    default: return "N/A";
  }
}

int oe_log_host_init(const char *path, uint64_t modules, log_level_t level)
{
   uint32_t ret = 1;
  // Validate input
  if (path == NULL || level > OE_LOG_ERROR)
    return ret;

  // Take the lock.
  if (oe_mutex_lock(&oe_log_lock) != 0)
    return ret;

  // Check is the log has been already initialized
  if (LogFile != NULL)
    goto cleanup;

  // Create log file
  LogFile = fopen(path, "w");
  if (LogFile == NULL)
    goto cleanup;

  LogModules = modules;
  LogLevel = level;
  ret = 0;

cleanup:
  // Release the lock.
  if (oe_mutex_unlock(&oe_log_lock) != 0)
    abort();

  return ret;
}

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave, uint64_t modules, log_level_t level)
{
  oe_result_t result = OE_UNEXPECTED;
  // Validate input
  if (level > OE_LOG_ERROR)
    return 1;

  //Populate arg fields.
  oe_log_filter_t *arg = calloc(1, sizeof(oe_log_filter_t));
  if (arg == NULL)
    OE_RAISE(OE_OUT_OF_MEMORY);

  arg->modules = modules;
  arg->level = level;

  // Call enclave
  OE_CHECK(oe_ecall(enclave, OE_ECALL_LOG_INIT, (uint64_t)arg, NULL));

  result = OE_OK;

done:
  return result;
}

void oe_log_close(void)
{
  // Take the lock.
  if (oe_mutex_lock(&oe_log_lock) != 0)
    return;
  // Close the log file
  if (LogFile != NULL)
  {
    fclose(LogFile);
    LogFile = NULL;
  }
  LogModules = 0;
  LogLevel = OE_LOG_NONE;
  // Release the lock.
  if (oe_mutex_unlock(&oe_log_lock) != 0)
    abort();
}

void oe_log(uint64_t module, log_level_t level, const char* fmt, ...)
{
  if (level < LogLevel || ((module & LogModules) == 0))
    return;
  if (!fmt)
    return;

  oe_log_args_t args;
  args.module = module;
  args.level = level;
  oe_va_list ap;
  oe_va_start(ap, fmt);
  oe_vsnprintf(args.message, OE_LOG_MESSAGE_LEN_MAX, fmt, ap);
  oe_va_end(ap);
  _oe_log(false, &args);
}

void _oe_log(bool enclave, oe_log_args_t *args)
{
  time_t t = time(NULL);
  struct tm *lt = localtime(&t);
  if (LogFile) {
    fprintf(LogFile, "%02d:%02d:%02d %s 0x%8x %-10s %-10s %s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      (enclave ? "E":"H"), args->module, log_module(args->module), log_level(args->level), args->message);
    fflush(LogFile);
  }
  printf("%02d:%02d:%02d %s 0x%8x %-10s %-10s %s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      (enclave ? "E":"H"), args->module, log_module(args->module), log_level(args->level), args->message);
}
