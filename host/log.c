// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "log.h"

static FILE *LogFile = NULL;
static int LogLevel = LOG_TRACE;

static const char* log_level(uint8_t level)
{
  switch (level) {
    case LOG_TRACE: return "TRACE";
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO: return "INFO";
    case LOG_WARN: return "WARN";
    case LOG_ERROR: return "ERROR";
    default: return "N/A";
  }
}

int log_init(int level, const char *path)
{
  if (path) {
    LogFile = fopen(path, "a");
    if (LogFile == NULL)
      return -1;
  }
  LogLevel = level;
  return 0;
}

void log_close() {
  if (LogFile != NULL)
  {
    fclose(LogFile);
    LogFile = NULL;
  }
}

void log_log(const char *enclave, oe_log_args_t *args) {
  if (args->level < LogLevel) {
    return;
  }
  time_t t = time(NULL);
  struct tm *lt = localtime(&t);
  if (LogFile) {
    fprintf(LogFile, "%02d:%02d:%02d %-5s %s:%s:%s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      log_level(args->level), enclave, args->module, args->message);
    fflush(LogFile);
  }
  printf(LogFile, "%02d:%02d:%02d %-5s %s:%s:%s\n", lt->tm_hour, lt->tm_min, lt->tm_sec,
      log_level(args->level), enclave, args->module, args->message);
}
