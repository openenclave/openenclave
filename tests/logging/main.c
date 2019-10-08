// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP \
    {                                          \
        {                                      \
        }                                      \
    }

#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include "../host/traceh.c"

void test_escaped_msg(const char* msg, const char* expected, bool expect_ok)
{
    size_t msg_size = strlen(msg);
    size_t max_msg_size = MAX_ESCAPED_MSG_MULTIPLIER * msg_size + 1;
    char* msg_escaped = malloc(max_msg_size);
    bool ok = _escape_characters(msg, msg_escaped, msg_size, max_msg_size);
    if (!ok || !expect_ok)
    {
        if (ok != expect_ok)
        {
            oe_put_err(
                "Expected escape result \"%s\" does not match actual escape "
                "result \"%s\". Original log: %s | escaped log: %s",
                expect_ok ? "true" : "false",
                ok ? "true" : "false",
                msg,
                msg_escaped);
        }
        free(msg_escaped);
        OE_TEST(!ok && !expect_ok);
        return;
    }
    OE_TEST(strcmp(msg_escaped, expected) == 0);
    free(msg_escaped);
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
#if defined(__linux__)
        test_escaped_msg(msg, "", false);
#else
        char expected[] = "?";
        test_escaped_msg(msg, expected, true);
#endif
    }
    {
        char msg[] = "\200";
#if defined(__linux__)
        test_escaped_msg(msg, "", false);
#else
        char expected[] = "?";
        test_escaped_msg(msg, expected, true);
#endif
    }
    {
        char msg[] = "\037";
        char expected[] = "\\\\u001f";
        test_escaped_msg(msg, expected, true);
    }
    {
        char msg[] = "\u2605\u0024";
#if defined(__linux__)
        test_escaped_msg(msg, "", false);
#else
        char expected[] = "?$";
        test_escaped_msg(msg, escaped, true);
#endif
    }
    {
        char msg[] = "\\\\\\\\";
        char expected[] = "\\\\\\\\\\\\\\\\";
        test_escaped_msg(msg, expected, true);
    }
    printf("=== passed TestEscapedCharachters()\n");
    return 0;
}

int main()
{
    TestEscapedCharacters();
    return 0;
}
