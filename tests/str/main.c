// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define MEM_MIN_CAP 1
#include <openenclave/internal/str.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

void TestStr(str_t* s)
{
    /* Test standard operations */
    {
        OE_TEST(str_ok(s));
        OE_TEST(str_len(s) == 0);
        OE_TEST(strcmp(str_ptr(s), "") == 0);

        OE_TEST(str_cpy(s, "hijk") == 0);
        OE_TEST(str_len(s) == 4);
        OE_TEST(strcmp(str_ptr(s), "hijk") == 0);

        OE_TEST(str_ncpy(s, "hijk???", 4) == 0);
        OE_TEST(str_len(s) == 4);
        OE_TEST(strcmp(str_ptr(s), "hijk") == 0);

        OE_TEST(str_ncpy(s, "hijk", 100) == 0);
        OE_TEST(str_len(s) == 4);
        OE_TEST(strcmp(str_ptr(s), "hijk") == 0);

        OE_TEST(str_cat(s, "lmnop") == 0);
        OE_TEST(str_len(s) == 9);
        OE_TEST(strcmp(str_ptr(s), "hijklmnop") == 0);

        OE_TEST(str_ncat(s, "qrstuv", 6) == 0);
        OE_TEST(str_len(s) == 15);
        OE_TEST(strcmp(str_ptr(s), "hijklmnopqrstuv") == 0);

        OE_TEST(str_catc(s, 'w') == 0);
        OE_TEST(str_catc(s, 'x') == 0);
        OE_TEST(str_catc(s, 'y') == 0);
        OE_TEST(str_catc(s, 'z') == 0);
        OE_TEST(str_len(s) == 19);
        OE_TEST(strcmp(str_ptr(s), "hijklmnopqrstuvwxyz") == 0);

        OE_TEST(str_insert(s, 0, "abcdefg") == 0);
        OE_TEST(str_len(s) == 26);
        OE_TEST(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        OE_TEST(str_remove(s, 11, 5) == 0);
        OE_TEST(str_len(s) == 21);
        OE_TEST(strcmp(str_ptr(s), "abcdefghijkqrstuvwxyz") == 0);

        OE_TEST(str_insert(s, 11, "lmnop") == 0);
        OE_TEST(str_len(s) == 26);
        OE_TEST(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        OE_TEST(str_remove(s, 22, 4) == 0);
        OE_TEST(str_len(s) == 22);
        OE_TEST(strcmp(str_ptr(s), "abcdefghijklmnopqrstuv") == 0);

        OE_TEST(str_ncat(s, "wxyz", (size_t)-1) == 0);
        OE_TEST(str_len(s) == 26);
        OE_TEST(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        OE_TEST(str_clear(s) == 0);
        OE_TEST(str_len(s) == 0);
        OE_TEST(str_cap(s) > 0);

        printf("=== passed standard tests\n");
    }

    /* Test str_substr() */
    {
        char buf[64];
        str_t substr;
        OE_TEST(str_static(&substr, buf, sizeof(buf)) == 0);
        OE_TEST(str_substr(&substr, "...substr...", 3, 6) == 0);
        OE_TEST(str_len(&substr) == 6);
        OE_TEST(strcmp(str_ptr(&substr), "substr") == 0);

        printf("=== passed str_substr()\n");
    }

    /* Test str_substr() */
    {
        char buf[64];
        str_t substr;
        OE_TEST(str_static(&substr, buf, sizeof(buf)) == 0);
        OE_TEST(str_substr(&substr, "...substr", 3, STR_NPOS) == 0);
        OE_TEST(str_len(&substr) == 6);
        OE_TEST(strcmp(str_ptr(&substr), "substr") == 0);

        printf("=== passed str_substr()\n");
    }

    /* Test str_substr() */
    {
        char buf[64];
        str_t substr;
        OE_TEST(str_static(&substr, buf, sizeof(buf)) == 0);
        OE_TEST(str_substr(&substr, "substr...", 0, 6) == 0);
        OE_TEST(str_len(&substr) == 6);
        OE_TEST(strcmp(str_ptr(&substr), "substr") == 0);

        printf("=== passed str_substr()\n");
    }

    /* Test sprintf */
    {
        OE_TEST(
            str_printf(
                s,
                "%s%s%s%s%s",
                "abcdefg",
                "hijk",
                "lmnop",
                "qrstuv",
                "wxyz") == 0);
        OE_TEST(str_len(s) == 26);
        OE_TEST(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        printf("=== passed str_replace()\n");
    }

    /* Test str_replace() */
    {
        str_cpy(s, "$0aaa$0bbb$0ccc$0");
        OE_TEST(str_len(s) == 17);
        OE_TEST(strcmp(str_ptr(s), "$0aaa$0bbb$0ccc$0") == 0);
        OE_TEST(str_replace(s, "$0", 2, "X", 1) == 0);
        OE_TEST(str_len(s) == 13);
        OE_TEST(strcmp(str_ptr(s), "XaaaXbbbXcccX") == 0);

        printf("=== passed str_replace()\n");
    }

    /* Test str_replace() */
    {
        str_cpy(s, "$0aaa$0bbb$0ccc$0");
        OE_TEST(str_len(s) == 17);
        OE_TEST(strcmp(str_ptr(s), "$0aaa$0bbb$0ccc$0") == 0);
        OE_TEST(str_replace(s, "$0", 2, "XYZ", 3) == 0);
        OE_TEST(str_len(s) == 21);
        OE_TEST(strcmp(str_ptr(s), "XYZaaaXYZbbbXYZcccXYZ") == 0);

        printf("=== passed str_replace()\n");
    }

    /* Test str_fgets() */
    {
        char buf[64];
        str_t str;
        OE_TEST(str_static(&str, buf, sizeof(buf)) == 0);
        FILE* is;
        size_t n = 1;
        int r;

#if defined(_WIN32)
        if (fopen_s(&is, "test1.txt", "r") != 0)
            OE_TEST(0);
#elif defined(__linux__)
        is = fopen("test1.txt", "r");
        OE_TEST(is);
#endif

        while ((r = str_fgets(&str, is)) == 0)
        {
            switch (n)
            {
                case 1:
                    OE_TEST(strcmp(str_ptr(&str), "red\n") == 0);
                    break;
                case 2:
                    OE_TEST(strcmp(str_ptr(&str), "green\n") == 0);
                    break;
                case 3:
                    OE_TEST(strcmp(str_ptr(&str), "blue\n") == 0);
                    break;
                case 4:
                    OE_TEST(strcmp(str_ptr(&str), "\n") == 0);
                    break;
                default:
                    OE_TEST(0);
            }

            n++;
        }

        OE_TEST(n == 5);
        OE_TEST(r == 1);

        fclose(is);

        printf("=== passed str_fgets()\n");
    }

    printf("=== passed TestStr()\n");
}

int main()
{
    /* TestStr dynamic */
    {
        str_t s;
        OE_TEST(str_dynamic(&s, NULL, 0) == 0);
        OE_TEST(str_cap(&s) == MEM_MIN_CAP);
        OE_TEST(str_reserve(&s, 2 * MEM_MIN_CAP) == 0);
        TestStr(&s);
        OE_TEST(str_free(&s) == 0);
    }

    /* TestStr static */
    {
        char buf[64];
        str_t s;
        OE_TEST(str_static(&s, buf, sizeof(buf)) == 0);
        OE_TEST(str_cap(&s) == sizeof(buf));
        OE_TEST(str_reserve(&s, sizeof(buf) + 1) == -1);
        TestStr(&s);
    }

    printf("=== passed all tests (str)\n");

    return 0;
}
