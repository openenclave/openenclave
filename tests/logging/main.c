// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int TestLoggingFormat(const char* path)
{
    OE_TRACE_ERROR("Hey");
    OE_TRACE_ERROR("Hello 'world'!");
    OE_TRACE_ERROR("Hello \"world\"! \n \\n \r \\r \t \\t \f \\f \? \\?");
    OE_TRACE_ERROR("\\u005C \u0024");
    OE_TRACE_ERROR("\\\\\\\\");
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
    printf("=== passed TestLoggingFormat()\n");
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
    OE_TEST(setenv("OE_JSON_ESCAPE", "true", true) == 0);
    return TestLoggingFormat(path);
}
