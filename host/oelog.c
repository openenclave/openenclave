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
static uint64_t LogFlags = 0;

static const char* log_flags(uint64_t flags)
{
  if (flags == OE_LOG_FLAGS_ALL)
  {
    return "ALL";
  }
  switch (flags)
  {
    case OE_LOG_FLAGS_ATTESTATION: return "ATTESTATION";
    case OE_LOG_FLAGS_GET_REPORT: return "GET_REPORT";
    case OE_LOG_FLAGS_VERIFY_REPORT: return "VERIFY_REPORT";
    case OE_LOG_FLAGS_COMMON: return "COMMON";
    case OE_LOG_FLAGS_CERT: return "CERT";
    case OE_LOG_FLAGS_TOOLS: return "TOOLS";
    case OE_LOG_FLAGS_CRYPTO: return "CRYPTO";
    case OE_LOG_FLAGS_SGX_SPECIFIC: return "SGX_SPECIFIC";
    case OE_LOG_FLAGS_IMAGE_LOADING: return "IMAGE_LOADING";
    default: return "N/A";
  }
}

static str2flags(void)
{
  const char *flags_str = getenv("OE_LOG_FLAGS");
  if (strlen(flags_str) == 0)
  {
    fprintf(stderr, "Environment variable OE_LOG_FLAGS is not set. Log is disabled\n");
    return 0;
  }
  uint64_t flags;
  int err;
  if (strncasecmp(flags_str, "0x", 2) == 0)
  {
    err = sscanf(flags_str, "0x%lx", &flags);
  }
  else
  {
    err = sscanf(flags_str, "%llu", &flags);
  }
  if (err != 0)
  {
    fprintf(stderr, "Invalid OE_LOG_FLAGS value '%s'. Log is disabled\n");
    return 0;
  }
  return flags;
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

static log_level_t str2log_level(void)
{
  const char *level_str = getenv("OE_LOG_LEVEL");
  if (strcasecmp(level_str, "DEBUG") == 0) return OE_LOG_DEBUG;
  if (strcasecmp(level_str, "INFO") == 0) return OE_LOG_INFO;
  if (strcasecmp(level_str, "WARN") == 0) return OE_LOG_WARN;
  if (strcasecmp(level_str, "ERROR") == 0) return OE_LOG_ERROR;
  if (strcasecmp(level_str, "NONE") == 0) return OE_LOG_NONE;
  fprintf(stderr, "Invalid log level %s. Expected DEBUG/INFO/WARN/ERROR\n");
  return OE_LOG_NONE;
}

int oe_log_host_init()
{
   uint32_t ret = 1;
   const char *path = getenv("OE_LOG_PATH");
   uint64_t flags = str2flags();
   log_level_t level = str2log_level();

  // Validate parameters
  if (path == NULL || level == OE_LOG_NONE || flags == 0)
    return ret;

  // Take the lock.
  if (oe_mutex_lock(&oe_log_lock) != 0) {
    fprintf(stderr, "Failed to acquire log lock. Log is disabled\n");
    return ret;
  }
  // Check is the log has been already initialized
  if (LogFile != NULL)
    goto cleanup;

  // Create log file
  LogFile = fopen(path, "w");
  if (LogFile == NULL)
  {
    fprintf(stderr, "Failed to create logfile %s\n");
    goto cleanup;
  }
  LogFlags = flags;
  LogLevel = level;
  ret = 0;

cleanup:
  // Release the lock.
  if (oe_mutex_unlock(&oe_log_lock) != 0)
    abort();

  return ret;
}

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
  oe_result_t result = OE_UNEXPECTED;
  uint64_t flags = str2flags();
  log_level_t level = str2log_level();

  // Validate parameters
  if (level == OE_LOG_NONE || flags == 0)
    return result;

  //Populate arg fields.
  oe_log_filter_t *arg = calloc(1, sizeof(oe_log_filter_t));
  if (arg == NULL)
    OE_RAISE(OE_OUT_OF_MEMORY);

  arg->flags = flags;
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
  LogFlags = 0;
  LogLevel = OE_LOG_NONE;
  // Release the lock.
  if (oe_mutex_unlock(&oe_log_lock) != 0)
    abort();
}

void oe_log(uint64_t flag, log_level_t level, const char* fmt, ...)
{
  if (level < LogLevel || ((flag & LogFlags) == 0))
    return;
  if (!fmt)
    return;

  oe_log_args_t args;
  args.flags = flags;
  args.level = level;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(args.message, OE_LOG_MESSAGE_LEN_MAX, fmt, ap);
  va_end(ap);
  _oe_log(false, &args);
}

void _oe_log(bool enclave, oe_log_args_t *args)
{
  time_t t = time(NULL);
  struct tm *lt = localtime(&t);
  if (LogFile) {
    fprintf(LogFile, "%02d:%02d:%02d %s 0x%08lx (%-16s) %-10s %s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      (enclave ? "E":"H"), args->flags, log_flags(args->flags), log_level(args->level), args->message);
    fflush(LogFile);
  }
  printf("%02d:%02d:%02d %s 0x%08lx (%-16s) %-10s %s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      (enclave ? "E":"H"), args->flags, log_flags(args->flags), log_level(args->level), args->message);
}
