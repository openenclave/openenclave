// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <sys/time.h>
#endif
#include <time.h>
#include "../hostthread.h"
#include "enclave.h"
#include "internal_u.h"

#define LOGGING_FORMAT_STRING "%02d:%02d:%02d:%06ld tid(0x%lx) (%s)[%s]%s"
static char* _log_level_strings[OE_LOG_LEVEL_MAX] =
    {"NONE", "FATAL", "ERROR", "WARN", "INFO", "VERBOSE"};
static oe_mutex _log_lock = OE_H_MUTEX_INITIALIZER;
static const char* _log_file_name = NULL;
static bool _log_creation_failed_before = false;
static oe_log_level_t _log_level = OE_LOG_LEVEL_ERROR;
static bool _initialized = false;

static oe_log_level_t _env2log_level(void)
{
    oe_log_level_t level = OE_LOG_LEVEL_ERROR;
    const char* level_str = getenv("OE_LOG_LEVEL");

    if (level_str == NULL)
    {
        goto done;
    }
    else if (strcmp(level_str, "VERBOSE") == 0)
    {
        level = OE_LOG_LEVEL_VERBOSE;
    }
    else if (strcmp(level_str, "INFO") == 0)
    {
        level = OE_LOG_LEVEL_INFO;
    }
    else if (strcmp(level_str, "WARNING") == 0)
    {
        level = OE_LOG_LEVEL_WARNING;
    }
    else if (strcmp(level_str, "ERROR") == 0)
    {
        level = OE_LOG_LEVEL_ERROR;
    }
    else if (strcmp(level_str, "FATAL") == 0)
    {
        level = OE_LOG_LEVEL_FATAL;
    }
    else if (strcmp(level_str, "NONE") == 0)
    {
        level = OE_LOG_LEVEL_NONE;
    }
done:
    return level;
}

static void _initialize_log_config()
{
    if (!_initialized)
    {
        // inititalize if not already
        _log_level = _env2log_level();
        _log_file_name = getenv("OE_LOG_DEVICE");
        _initialized = true;
    }
}

static void _write_header_info_to_stream(FILE* stream)
{
    time_t t = time(NULL);
    struct tm* lt = localtime(&t);

    fprintf(
        stream, "================= New logging session =================\n");
    fprintf(stream, "%s", asctime(lt));
    fprintf(
        stream,
        "https://github.com/openenclave/openenclave branch:%s\n",
        OE_REPO_BRANCH_NAME);
    fprintf(stream, "Last commit:%s\n\n", OE_REPO_LAST_COMMIT);
}

static void _write_message_to_stream(
    FILE* stream,
    bool is_enclave,
    oe_log_level_t level,
    const char* message)
{
#if defined(__linux__)
    struct timeval time_now;
    gettimeofday(&time_now, NULL);
    struct tm* t = gmtime(&time_now.tv_sec);
#else
    time_t lt = time(NULL);
    struct tm* t = localtime(&lt);
#endif

    oe_thread thread_id = oe_thread_self();

    fprintf(
        stream,
        LOGGING_FORMAT_STRING,
        t->tm_hour,
        t->tm_min,
        t->tm_sec,
#if defined(__linux__)
        time_now.tv_usec,
#else
        0,
#endif
        thread_id,
        (is_enclave ? "E" : "H"),
        _log_level_strings[level],
        message);
}

static void _log_session_header()
{
    if (!_log_file_name)
    {
        return;
    }

    // Take the log file lock.
    if (!_log_creation_failed_before)
    {
        if (oe_mutex_lock(&_log_lock) == OE_OK)
        {
            FILE* log_file = NULL;
            log_file = fopen(_log_file_name, "a");
            if (log_file == NULL)
            {
                fprintf(
                    stderr, "Failed to create logfile %s\n", _log_file_name);
                oe_mutex_unlock(&_log_lock);
                _log_creation_failed_before = true;
                return;
            }

            _write_header_info_to_stream(log_file);
            fflush(log_file);
            fclose(log_file);
            oe_mutex_unlock(&_log_lock);
        }
    }
}

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
    _initialize_log_config();

    return oe_log_init_ecall(enclave, enclave->path, _log_level);
}

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...)
{
    oe_result_t result = OE_UNEXPECTED;
    char message[OE_LOG_MESSAGE_LEN_MAX];
    va_list ap;

    if (!fmt)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (_initialized)
    {
        if (level > _log_level)
        {
            result = OE_OK;
            goto done;
        }
    }

    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    oe_log_message(false, level, message);

    result = OE_OK;

done:
    return result;
}

// This is an expensive operation, it involves acquiring lock
// and file operation.
void oe_log_message(bool is_enclave, oe_log_level_t level, const char* message)
{
    if (!_initialized)
    {
        _initialize_log_config();
        _log_session_header();
    }
    if (_initialized)
    {
        if (level > _log_level)
            return;
    }

    // Take the log file lock.
    if (oe_mutex_lock(&_log_lock) == OE_OK)
    {
        if (!_log_file_name)
        {
            _write_message_to_stream(stdout, is_enclave, level, message);
        }
        else if (!_log_creation_failed_before)
        {
            FILE* log_file = NULL;
            log_file = fopen(_log_file_name, "a");
            if (log_file == NULL)
            {
                fprintf(
                    stderr, "Failed to create logfile %s\n", _log_file_name);
                oe_mutex_unlock(&_log_lock);
                _log_creation_failed_before = true;
                return;
            }
            _write_message_to_stream(log_file, is_enclave, level, message);
            fflush(log_file);
            fclose(log_file);
        }
        // Release the log file lock.
        oe_mutex_unlock(&_log_lock);
    }
}

oe_log_level_t oe_get_current_logging_level(void)
{
    return _log_level;
}
