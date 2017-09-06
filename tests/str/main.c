#define MEM_MIN_CAP 1
#include <assert.h>
#include <stdio.h>
#include <openenclave/bits/str.h>

void TestStr(str_t* s)
{
    /* Test standard operations */
    {
        assert(str_ok(s));
        assert(str_len(s) == 0);
        assert(strcmp(str_ptr(s), "") == 0);

        assert(str_cpy(s, "hijk") == 0);
        assert(str_len(s) == 4);
        assert(strcmp(str_ptr(s), "hijk") == 0);

        assert(str_ncpy(s, "hijk???", 4) == 0);
        assert(str_len(s) == 4);
        assert(strcmp(str_ptr(s), "hijk") == 0);

        assert(str_ncpy(s, "hijk", 100) == 0);
        assert(str_len(s) == 4);
        assert(strcmp(str_ptr(s), "hijk") == 0);

        assert(str_cat(s, "lmnop") == 0);
        assert(str_len(s) == 9);
        assert(strcmp(str_ptr(s), "hijklmnop") == 0);

        assert(str_ncat(s, "qrstuv", 6) == 0);
        assert(str_len(s) == 15);
        assert(strcmp(str_ptr(s), "hijklmnopqrstuv") == 0);

        assert(str_catc(s, 'w') == 0);
        assert(str_catc(s, 'x') == 0);
        assert(str_catc(s, 'y') == 0);
        assert(str_catc(s, 'z') == 0);
        assert(str_len(s) == 19);
        assert(strcmp(str_ptr(s), "hijklmnopqrstuvwxyz") == 0);

        assert(str_insert(s, 0, "abcdefg") == 0);
        assert(str_len(s) == 26);
        assert(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        assert(str_remove(s, 11, 5) == 0);
        assert(str_len(s) == 21);
        assert(strcmp(str_ptr(s), "abcdefghijkqrstuvwxyz") == 0);

        assert(str_insert(s, 11, "lmnop") == 0);
        assert(str_len(s) == 26);
        assert(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        assert(str_remove(s, 22, 4) == 0);
        assert(str_len(s) == 22);
        assert(strcmp(str_ptr(s), "abcdefghijklmnopqrstuv") == 0);

        assert(str_ncat(s, "wxyz", (size_t)-1) == 0);
        assert(str_len(s) == 26);
        assert(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        assert(str_clear(s) == 0);
        assert(str_len(s) == 0);
        assert(str_cap(s) > 0);

        printf("=== passed standard tests\n");
    }

    /* Test str_substr() */
    {
        char buf[64];
        str_t substr;
        assert(str_static(&substr, buf, sizeof(buf)) == 0);
        assert(str_substr(&substr, "...substr...", 3, 6) == 0);
        assert(str_len(&substr) == 6);
        assert(strcmp(str_ptr(&substr), "substr") == 0);

        printf("=== passed str_substr()\n");
    }

    /* Test str_substr() */
    {
        char buf[64];
        str_t substr;
        assert(str_static(&substr, buf, sizeof(buf)) == 0);
        assert(str_substr(&substr, "...substr", 3, STR_NPOS) == 0);
        assert(str_len(&substr) == 6);
        assert(strcmp(str_ptr(&substr), "substr") == 0);

        printf("=== passed str_substr()\n");
    }

    /* Test str_substr() */
    {
        char buf[64];
        str_t substr;
        assert(str_static(&substr, buf, sizeof(buf)) == 0);
        assert(str_substr(&substr, "substr...", 0, 6) == 0);
        assert(str_len(&substr) == 6);
        assert(strcmp(str_ptr(&substr), "substr") == 0);

        printf("=== passed str_substr()\n");
    }

    /* Test sprintf */
    {
        assert(str_printf(s, "%s%s%s%s%s", 
            "abcdefg", "hijk", "lmnop", "qrstuv", "wxyz") == 0);
        assert(str_len(s) == 26);
        assert(strcmp(str_ptr(s), "abcdefghijklmnopqrstuvwxyz") == 0);

        printf("=== passed str_replace()\n");
    }

    /* Test str_replace() */
    {
        str_cpy(s, "$0aaa$0bbb$0ccc$0");
        assert(str_len(s) == 17);
        assert(strcmp(str_ptr(s), "$0aaa$0bbb$0ccc$0") == 0);
        assert(str_replace(s, "$0", 2, "X", 1) == 0);
        assert(str_len(s) == 13);
        assert(strcmp(str_ptr(s), "XaaaXbbbXcccX") == 0);

        printf("=== passed str_replace()\n");
    }

    /* Test str_replace() */
    {
        str_cpy(s, "$0aaa$0bbb$0ccc$0");
        assert(str_len(s) == 17);
        assert(strcmp(str_ptr(s), "$0aaa$0bbb$0ccc$0") == 0);
        assert(str_replace(s, "$0", 2, "XYZ", 3) == 0);
        assert(str_len(s) == 21);
        assert(strcmp(str_ptr(s), "XYZaaaXYZbbbXYZcccXYZ") == 0);

        printf("=== passed str_replace()\n");
    }

    /* Test str_fgets() */
    {
        char buf[64];
        str_t str;
        assert(str_static(&str, buf, sizeof(buf)) == 0);
        FILE* is;
        size_t n = 1;
        int r;

        is = fopen("test1.txt", "r");
        assert(is);

        while ((r = str_fgets(&str, is)) == 0)
        {
            switch (n)
            {
                case 1:
                    assert(strcmp(str_ptr(&str), "red\n") == 0);
                    break;
                case 2:
                    assert(strcmp(str_ptr(&str), "green\n") == 0);
                    break;
                case 3:
                    assert(strcmp(str_ptr(&str), "blue\n") == 0);
                    break;
                case 4:
                    assert(strcmp(str_ptr(&str), "\n") == 0);
                    break;
                default:
                    assert(0);
            }

            n++;
        }

        assert(n = 4);
        assert(r == 1);

        fclose(is);

        printf("=== passed str_fgets()\n");
    }

    printf("=== passed TestStr()\n");
}

int main(int argc, const char* argv[])
{
    /* TestStr dynamic */
    {
        str_t s;
        assert(str_dynamic(&s, NULL, 0) == 0);
        assert(str_cap(&s) == MEM_MIN_CAP);
        assert(str_reserve(&s, 2 * MEM_MIN_CAP) == 0);
        TestStr(&s);
        assert(str_free(&s) == 0);
    }

    /* TestStr static */
    {
        char buf[64];
        str_t s;
        assert(str_static(&s, buf, sizeof(buf)) == 0);
        assert(str_cap(&s) == sizeof(buf));
        assert(str_reserve(&s, sizeof(buf) + 1) == -1);
        TestStr(&s);
    }

    printf("=== passed all tests (str)\n");

    return 0;
}
