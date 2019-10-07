// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
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
#include "hostthread.h"

#define LOGGING_FORMAT_STRING "%s.%06ldZ [(%s)%s] tid(0x%lx) | %s"

static char* _log_level_strings[OE_LOG_LEVEL_MAX] =
    {"NONE", "FATAL", "ERROR", "WARN", "INFO", "VERBOSE"};
static oe_mutex _log_lock = OE_H_MUTEX_INITIALIZER;
static const char* _log_file_name = NULL;
static const char* _custom_log_format = NULL;
static const char* _log_all_streams = NULL;
static const char* _log_escape = NULL;
static bool _log_creation_failed_before = false;
static const size_t MAX_ESCAPED_CHAR_LEN = 5; // e.g. u2605
static const size_t MAX_ESCAPED_MSG_MULTIPLIER =
    7; // MAX_ESCAPED_CHAR_LEN + sizeof("\\\\")
oe_log_level_t _log_level = OE_LOG_LEVEL_ERROR;
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

void initialize_log_config()
{
    if (!_initialized)
    {
        // inititalize if not already
        _log_level = _env2log_level();
        _log_file_name = getenv("OE_LOG_DEVICE");
        _custom_log_format = getenv("OE_LOG_FORMAT");
        _log_all_streams = getenv("OE_LOG_ALL_STREAMS");
        _log_escape = getenv("OE_LOG_JSON_ESCAPE");
        if (_custom_log_format)
        {
            // check that custom log format string terminates with a line return
            size_t len = strlen(_custom_log_format);
            if (_custom_log_format[len - 1] != '\n')
            {
                fprintf(
                    stderr,
                    "%s\n",
                    "[ERROR] Custom log format does not end with a newline");
                exit(1);
            }
        }
        _initialized = true;
    }
}

static bool _escape_characters(
    const char* log_msg,
    char* log_msg_escaped,
    size_t msg_size,
    size_t max_msg_size)
{
    size_t idx = 0;
    for (size_t i = 0; i < msg_size; i++)
    {
        int c = log_msg[i];
        if (log_msg[i] == '\"')
        {
            // single quotes are OK for JSON
            log_msg_escaped[idx] = '\'';
        }
        else if (log_msg[i] == '\\')
        {
            log_msg_escaped[idx] = '\\';
            idx++;
            log_msg_escaped[idx] = '\\';
        }
        else if (!isprint(c))
        {
            log_msg_escaped[idx] = '\\';
            idx++;
            log_msg_escaped[idx] = '\\';
            idx++;
            switch (log_msg[i])
            {
                case '\b':
                    log_msg_escaped[idx] = 'b';
                    break;
                case '\f':
                    log_msg_escaped[idx] = 'f';
                    break;
                case '\n':
                    log_msg_escaped[idx] = 'n';
                    break;
                case '\r':
                    log_msg_escaped[idx] = 'r';
                    break;
                case '\t':
                    log_msg_escaped[idx] = 't';
                    break;
                default:
                    if ((uint8_t)log_msg[i] > 127 /* max ASCII value */)
                    {
                        return false;
                    }
                    sprintf(
                        (char*)&log_msg_escaped[idx], "u%04hhx", log_msg[i]);
                    // idx is also incremented after switch case
                    idx += MAX_ESCAPED_CHAR_LEN - 1;
                    break;
            }
        }
        else
        {
            log_msg_escaped[idx] = log_msg[i];
        }
        idx++;
    }
    if (idx < max_msg_size)
    {
        log_msg_escaped[idx] = '\0';
    }
    return true;
}

static void _write_message_to_stream(
    FILE* stream,
    bool is_enclave,
    const char* time,
    long int usecs,
    oe_log_level_t level,
    const char* message)
{
    fprintf(
        stream,
        LOGGING_FORMAT_STRING,
        time,
        usecs,
        (is_enclave ? "E" : "H"),
        _log_level_strings[level],
        oe_thread_self(),
        message);
}

static void _write_custom_format_message_to_stream(
    FILE* stream,
    bool is_enclave,
    const char* time,
    long int usecs,
    oe_log_level_t level,
    const char* message,
    const char* file,
    const char* function,
    const char* number,
    const char* log_format)
{
    fprintf(
        stream,
        log_format,
        time,
        usecs,
        (is_enclave ? "E" : "H"),
        _log_level_strings[level],
        oe_thread_self(),
        message,
        file,
        function,
        number);
}

oe_result_t oe_log(oe_log_level_t level, const char* fmt, ...)
{
    oe_result_t result = OE_UNEXPECTED;
    char* message = NULL;
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

    if (!(message = malloc(OE_LOG_MESSAGE_LEN_MAX)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    va_start(ap, fmt);
    vsnprintf(message, OE_LOG_MESSAGE_LEN_MAX, fmt, ap);
    va_end(ap);
    oe_log_message(false, level, message);

    result = OE_OK;

done:

    if (message)
        free(message);

    return result;
}

// This is an expensive operation, it involves acquiring lock
// and file operation.
void oe_log_message(bool is_enclave, oe_log_level_t level, const char* message)
{
    // get timestamp for log
#if defined(__linux__)
    struct timeval time_now;
    gettimeofday(&time_now, NULL);
    struct tm* t = gmtime(&time_now.tv_sec);
#else
    time_t lt = time(NULL);
    struct tm* t = gmtime(&lt);
#endif

    char time[20];
    strftime(time, sizeof(time), "%Y-%m-%dT%H:%M:%S", t);

#if defined(__linux__)
    long int usecs = time_now.tv_usec;
#else
    long int usecs = 0;
#endif
    if (!_initialized)
    {
        initialize_log_config();
    }
    if (_initialized)
    {
        if (level > _log_level)
            return;
    }

    // Take the log file lock.
    if (oe_mutex_lock(&_log_lock) == OE_OK)
    {
        if (_log_all_streams || !_log_file_name)
        {
            _write_message_to_stream(
                stdout, is_enclave, time, usecs, level, message);
        }

        if (!_log_file_name)
        {
            // Release the log file lock.
            oe_mutex_unlock(&_log_lock);
            return;
        }

        if (!_log_creation_failed_before)
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

            if (!_custom_log_format)
            {
                _write_message_to_stream(
                    log_file, is_enclave, time, usecs, level, message);
            }
            else
            {
                char* message_cursor = NULL;
#if defined(__linux__)
                char* log_msg = strtok_r((char*)message, "[", &message_cursor);
                char* file_name = strtok_r(NULL, ":", &message_cursor);
                char* function = strtok_r(NULL, ":", &message_cursor);
                char* line_number = strtok_r(NULL, "]", &message_cursor);
#else
                char* log_msg = strtok_s((char*)message, "[", &message_cursor);
                char* file_name = strtok_s(NULL, ":", &message_cursor);
                char* function = strtok_s(NULL, ":", &message_cursor);
                char* line_number = strtok_s(NULL, "]", &message_cursor);
#endif
                if (!log_msg || !file_name || !function || !line_number)
                {
                    _write_message_to_stream(
                        log_file,
                        is_enclave,
                        time,
                        usecs,
                        level,
                        "Failed to apply custom formatter to message\n");
                }
                else
                {
                    if (_log_escape)
                    {
                        size_t msg_size = strlen(log_msg);
                        size_t max_msg_size =
                            MAX_ESCAPED_MSG_MULTIPLIER * msg_size + 1;
                        char* log_msg_escaped = malloc(max_msg_size);
                        bool escaped_ok = _escape_characters(
                            log_msg, log_msg_escaped, msg_size, max_msg_size);

                        _write_custom_format_message_to_stream(
                            log_file,
                            is_enclave,
                            time,
                            usecs,
                            level,
                            (escaped_ok ? log_msg_escaped
                                        : "failed to escape log message"),
                            file_name,
                            function,
                            line_number,
                            _custom_log_format);

                        free(log_msg_escaped);
                    }
                    else
                    {
                        _write_custom_format_message_to_stream(
                            log_file,
                            is_enclave,
                            time,
                            usecs,
                            level,
                            log_msg,
                            file_name,
                            function,
                            line_number,
                            _custom_log_format);
                    }
                }
            }

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
