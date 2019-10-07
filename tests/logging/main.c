// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP \
    {                                          \
        {                                      \
        }                                      \
    }

#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../host/traceh.c"

void test_line_format(const char* line)
{
    OE_TEST(strstr(line, "e_ts") != NULL);
    OE_TEST(strstr(line, "level") != NULL);
    OE_TEST(strstr(line, "tid") != NULL);
    OE_TEST(strstr(line, "msg") != NULL);
    OE_TEST(strstr(line, "file") != NULL);
    OE_TEST(strstr(line, "func") != NULL);
    OE_TEST(strstr(line, "number") != NULL);
}

void test_escaped_msg(const char* msg, const char* expected, bool expect_ok)
{
    size_t msg_size = strlen(msg);
    size_t max_msg_size = MAX_ESCAPED_MSG_MULTIPLIER * msg_size + 1;
    char* msg_escaped = malloc(max_msg_size);
    bool ok = _escape_characters(msg, msg_escaped, msg_size, max_msg_size);
    if (!expect_ok)
    {
        free(msg_escaped);
        OE_TEST(!ok);
        return;
    }
    OE_TEST(strcmp(msg_escaped, expected) == 0);
    free(msg_escaped);
}

int TestLoggingFormat(const char* path)
{
    OE_TRACE_ERROR("Hey");
    OE_TRACE_ERROR("Hello 'world'!");
    OE_TRACE_ERROR("Hello \"world\"!");
    OE_TRACE_ERROR("/ \\/ \' \a \\a \b \\b \e \\e \f \\f \n \\n \r \\r \t \\t "
                   "\v \\v \? \\?");
    OE_TRACE_ERROR("\\u005C \u0024 \u0040 @");
    OE_TRACE_ERROR("\\\\\\\\");
    OE_TRACE_ERROR("\u2605");
    OE_TRACE_ERROR("\01");
    OE_TRACE_ERROR("\037");
    OE_TRACE_ERROR("\024");
    OE_TRACE_ERROR("\200");
    OE_TRACE_ERROR("\u2605\u0024");
    FILE* log_file = fopen(path, "r");
    char* line = NULL;
    size_t len = 0;
    if (log_file == NULL)
    {
        fprintf(stderr, "Failed to OPEN logfile %s\n", "out.log");
        return 1;
    }

    while (getline(&line, &len, log_file) != -1)
    {
        test_line_format(line);
    }
    fclose(log_file);
    printf("=== passed TestLoggingFormat()\n");
    return 0;
}

int TestEscapedCharacters()
{
    {
        char msg[] = "Hey";
        char expected[] = "Hey";
        test_escaped_msg(msg, expected, true);
    }
    {
        char msg[] = "\u2605";
        test_escaped_msg(msg, "", false);
    }
    {
        char msg[] = "\200";
        test_escaped_msg(msg, "", false);
    }
    {
        char msg[] = "\037";
        char expected[] = "\\\\u001f";
        test_escaped_msg(msg, expected, true);
    }
    {
        char msg[] = "\u2605\u0024";
        test_escaped_msg(msg, "", false);
    }
    {
        char msg[] = "\\\\\\\\";
        char expected[] = "\\\\\\\\\\\\\\\\";
        test_escaped_msg(msg, expected, true);
    }
    printf("=== passed TestEscapedCharachters()\n");
    return 0;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s LOG_FILE_PATH\n", argv[0]);
        return 1;
    }

    const char* path = argv[1];
    OE_TEST(setenv("OE_LOG_DEVICE", path, true) == 0);
    OE_TEST(
        setenv(
            "OE_LOG_FORMAT",
            "{\"e_ts\":\"%s.%06ldZ\",\"level\":\"(%s)%s\",\"tid\":\"tid(0x%lx)"
            "\",\"msg\":\"%s\",\"file\":\"%s\",\"func\":\"%s\",\"number\":\"%"
            "s\"}\n",
            true) == 0);
    OE_TEST(setenv("OE_LOG_JSON_ESCAPE", "true", true) == 0);
    TestEscapedCharacters();
    TestLoggingFormat(path);
    return 0;
}
