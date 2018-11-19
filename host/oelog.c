// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/oelog-host.h>
#include "enclave.h"
#include "hostthread.h"

static oe_mutex oe_log_lock = OE_H_MUTEX_INITIALIZER;
static FILE *LogFile = NULL;
static log_level_t LogLevel = OE_LOG_NONE;

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

int oe_log_init(const char *path, log_level_t level)
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

  LogLevel = level;
  ret = 0;

cleanup:
  // Release the lock.
  if (oe_mutex_unlock(&oe_log_lock) != 0)
    abort();

  return ret;
}

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave, log_level_t level)
{
  oe_result_t result = OE_UNEXPECTED;
  // Validate input
  if (level > OE_LOG_ERROR)
    return 1;
  // Call enclave
  OE_CHECK(oe_ecall(enclave, OE_ECALL_LOG_INIT, (uint64_t)level, NULL));

  result = OE_OK;

done:
  return result;
}

void oe_log_close(void) {
  // Take the lock.
  if (oe_mutex_lock(&oe_log_lock) != 0)
    return;
  // Close the log file
  if (LogFile != NULL)
  {
    fclose(LogFile);
    LogFile = NULL;
  }
  LogLevel = OE_LOG_NONE;
  // Release the lock.
  if (oe_mutex_unlock(&oe_log_lock) != 0)
    abort();
}

void log_log(const char *enclave, oe_log_args_t *args) {
  time_t t = time(NULL);
  struct tm *lt = localtime(&t);
  if (LogFile) {
    fprintf(LogFile, "%02d:%02d:%02d %-5s %s:%s:%s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      log_level(args->level), enclave, args->module, args->message);
    fflush(LogFile);
  }
  printf("%02d:%02d:%02d %-5s %s:%s:%s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      log_level(args->level), enclave, args->module, args->message);
}
