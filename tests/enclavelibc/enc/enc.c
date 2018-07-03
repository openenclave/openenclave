// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

static int _test_setjmp_aux(void)
{
    oe_jmp_buf buf;

    int rc = oe_setjmp(buf);

    if (rc == 999)
        return rc;

    oe_longjmp(buf, 999);
    return 0;
}

static void _test_setjmp(void)
{
    OE_TEST(_test_setjmp_aux() == 999);
}

static void _test_strdup(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    {
        char* s = oe_strdup("hello");
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "hello") == 0);
        oe_free(s);
    }

    {
        char* s = oe_strdup("");
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "") == 0);
        oe_free(s);
    }

    {
        char* s = oe_strndup("hello world", 5);
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "hello") == 0);
        oe_free(s);
    }

    {
        char* s = oe_strndup("hello world", 0);
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "") == 0);
        oe_free(s);
    }

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strcasecmp()
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    OE_TEST(oe_strcasecmp("abc", "ABC") == 0);
    OE_TEST(oe_strcasecmp("abc", "AbC") == 0);
    OE_TEST(oe_strcasecmp("abc", "AbCx") != 0);
    OE_TEST(oe_strcasecmp("abc", "xyz") != 0);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_oe_snprintf()
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    int n;
    char buf[256];

    n = oe_snprintf(buf, sizeof(buf), "abc %u %x %s", 1, 2, "xyz");
    OE_TEST(oe_strcmp(buf, "abc 1 2 xyz") == 0);
    OE_TEST(n == oe_strlen(buf));

    n = oe_snprintf(buf, sizeof(buf), "%ld %lx\n", 1L, 2L);
    OE_TEST(oe_strcmp(buf, "1 2\n") == 0);
    OE_TEST(n == oe_strlen(buf));

    n = oe_snprintf(buf, sizeof(buf), "%zd", -1L);
    OE_TEST(oe_strcmp(buf, "-1") == 0);
    OE_TEST(n == oe_strlen(buf));

    n = oe_snprintf(buf, sizeof(buf), "0x%x", 0x12345678);
    OE_TEST(oe_strcmp(buf, "0x12345678") == 0);
    OE_TEST(n == oe_strlen(buf));

    n = oe_snprintf(buf, sizeof(buf), "0x%lx", 0x12345678ABCDEF01);
    OE_TEST(oe_strcmp(buf, "0x12345678abcdef01") == 0);
    OE_TEST(n == oe_strlen(buf));

    n = oe_snprintf(buf, sizeof(buf), "zzzzzzzz: '%-10.5lu'\n", 1234567UL);
    OE_TEST(n == oe_strlen(buf));
    OE_TEST(oe_strcmp(buf, "zzzzzzzz: '1234567   '\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "1: '%10d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "1: '     12345'\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "2: '%010d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "2: '0000012345'\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "3: '%-10d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "3: '12345     '\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "4: '%10.20d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "4: '00000000000000012345'\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "5: '%-10.20d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "5: '00000000000000012345'\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "6: '%20.10d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "6: '          0000012345'\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "7: '%-20.10d'\n", 12345);
    OE_TEST(oe_strcmp(buf, "7: '0000012345          '\n") == 0);

    n = oe_snprintf(buf, sizeof(buf), "%x", 0x1);
    OE_TEST(oe_strcmp(buf, "1") == 0);

    n = oe_snprintf(buf, sizeof(buf), "%08x", 0xa);
    OE_TEST(oe_strcmp(buf, "0000000a") == 0);

    n = oe_snprintf(buf, sizeof(buf), "%#X", 0xabcdef01);
    OE_TEST(oe_strcmp(buf, "0XABCDEF01") == 0);

    n = oe_snprintf(buf, sizeof(buf), "%o", 01234567);
    OE_TEST(oe_strcmp(buf, "1234567") == 0);

    n = oe_snprintf(buf, sizeof(buf), "%#o", 0777);
    OE_TEST(oe_strcmp(buf, "0777") == 0);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_malloc()
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    static const size_t N = 1000;
    char* p[N];

    for (size_t i = 0; i < N; i++)
        OE_TEST((p[i] = oe_malloc(1024)) != NULL);

    for (size_t i = 0; i < N; i++)
        oe_free(p[i]);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strtoul()
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    char* end;
    uint64_t x;

    x = oe_strtoul("123456789abcdefg", &end, 10);
    OE_TEST(oe_strcmp(end, "abcdefg") == 0);
    OE_TEST(x == 123456789UL);

    x = oe_strtoul("12345999", &end, 8);
    OE_TEST(oe_strcmp(end, "999") == 0);
    OE_TEST(x == 012345);

    x = oe_strtoul("ABCDEF12hello", &end, 16);
    OE_TEST(oe_strcmp(end, "hello") == 0);
    OE_TEST(x == 0xABCDEF12);

    x = oe_strtoul("0111222", &end, 2);
    OE_TEST(oe_strcmp(end, "222") == 0);
    OE_TEST(x == 7);

    x = oe_strtoul("0yyy", &end, 8);
    OE_TEST(oe_strcmp(end, "yyy") == 0);
    OE_TEST(x == 0);

    x = oe_strtoul("0mmm", &end, 0);
    OE_TEST(oe_strcmp(end, "mmm") == 0);
    OE_TEST(x == 0);

    x = oe_strtoul("-9223372036854775807", &end, 0);
    OE_TEST(x == 9223372036854775809UL);

    x = oe_strtoul("-9223372036854775808", &end, 0);
    OE_TEST(x == 9223372036854775808UL);

    x = oe_strtoul("-1", &end, 0);
    OE_TEST(x == 18446744073709551615UL);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strcpy()
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    char buf[16];
    oe_strcpy(buf, "strcpy");
    OE_TEST(oe_strcmp(buf, "strcpy") == 0);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

OE_ENCLAVELIBC_PRINTF_FORMAT(2, 3)
static bool _test(const char* expect, const char* format, ...)
{
    char buf[1024];

    oe_va_list ap;
    oe_va_start(ap, format);
    *buf = '\0';
    oe_va_start(ap, format);
    int n = oe_vsnprintf(buf, sizeof(buf), format, ap);
    oe_va_end(ap);

    if (n < 0)
        return false;

    if (oe_strcmp(buf, expect) != 0)
        return false;

    if (oe_strlen(expect) != n)
        return false;

    return true;
}

static void _test_printf(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    OE_TEST(_test("'1234567890'", "'%10.5u'", 1234567890));
    OE_TEST(_test("'   abc'", "'%6s'", "abc"));
    OE_TEST(_test("'abcdefg'", "'%.*s'", 7, "abcdefghijklmnopqrstuvwxyz"));
    OE_TEST(_test("abc 1 2 xyz", "abc %u %x %s", 1, 2, "xyz"));
    OE_TEST(_test("1 2\n", "%ld %lx\n", 1L, 2L));
    OE_TEST(_test("-1", "%zd", -1L));
    OE_TEST(_test("0x12345678", "0x%x", 0x12345678));
    OE_TEST(_test("0x12345678abcdef01", "0x%lx", 0x12345678ABCDEF01));
    OE_TEST(_test("0x12345678ABCDEF01", "0x%lX", 0x12345678ABCDEF01));
    OE_TEST(_test("0x12345678abcdef01", "0x%lx", 0x12345678ABCDEF01));
    OE_TEST(_test("zzzzzzzz: '1234567   '", "zzzzzzzz: '%-10.5lu'", 1234567UL));
    OE_TEST(_test("1: '     12345'\n", "1: '%10d'\n", 12345));
    OE_TEST(_test("2: '0000012345'\n", "2: '%010d'\n", 12345));
    OE_TEST(_test("3: '12345     '\n", "3: '%-10d'\n", 12345));
    OE_TEST(_test("4: '00000000000000012345'\n", "4: '%10.20d'\n", 12345));
    OE_TEST(_test("5: '00000000000000012345'\n", "5: '%-10.20d'\n", 12345));
    OE_TEST(_test("6: '          0000012345'\n", "6: '%20.10d'\n", 12345));
    OE_TEST(_test("7: '0000012345          '\n", "7: '%-20.10d'\n", 12345));
    OE_TEST(_test("1\n", "%x\n", 0x1));
    OE_TEST(_test("0000000a\n", "%08x\n", 0xa));
    OE_TEST(_test("0XABCDEF01\n", "%#X\n", 0xabcdef01));
    OE_TEST(_test("1234567\n", "%o\n", 01234567));
    OE_TEST(_test("0777\n", "%#o\n", 0777));
    OE_TEST(_test("1\n", "%u\n", 1));
    OE_TEST(_test("A\n", "%c\n", 'A'));
    OE_TEST(_test("       A\n", "%8c\n", 'A'));
    OE_TEST(_test("00000000\n", "%08o\n", 0));

    OE_TEST(_test("32767\n", "%d\n", OE_SHRT_MAX));
    OE_TEST(_test("-32768\n", "%d\n", OE_SHRT_MIN));
    OE_TEST(_test("65535\n", "%u\n", OE_USHRT_MAX));

    OE_TEST(_test("2147483647\n", "%d\n", OE_INT_MAX));
    OE_TEST(_test("-2147483648\n", "%d\n", OE_INT_MIN));
    OE_TEST(_test("4294967295\n", "%u\n", OE_UINT_MAX));

    OE_TEST(_test("9223372036854775807\n", "%ld\n", OE_LONG_MAX));
    OE_TEST(_test("-9223372036854775808\n", "%ld\n", OE_LONG_MIN));
    OE_TEST(_test("18446744073709551615\n", "%lu\n", OE_ULONG_MAX));

    OE_TEST(_test("9223372036854775807\n", "%lld\n", OE_LLONG_MAX));
    OE_TEST(_test("-9223372036854775808\n", "%lld\n", OE_LLONG_MIN));
    OE_TEST(_test("18446744073709551615\n", "%llu\n", OE_ULLONG_MAX));

    OE_TEST(_test("-128\n", "%d\n", OE_INT8_MIN));
    OE_TEST(_test("127\n", "%d\n", OE_INT8_MAX));
    OE_TEST(_test("255\n", "%u\n", OE_UINT8_MAX));

    OE_TEST(_test("-32768\n", "%d\n", OE_INT16_MIN));
    OE_TEST(_test("32767\n", "%d\n", OE_INT16_MAX));
    OE_TEST(_test("65535\n", "%u\n", OE_UINT16_MAX));

    OE_TEST(_test("-2147483648\n", "%d\n", OE_INT32_MIN));
    OE_TEST(_test("2147483647\n", "%d\n", OE_INT32_MAX));
    OE_TEST(_test("4294967295\n", "%u\n", OE_UINT32_MAX));

    OE_TEST(_test("-9223372036854775808\n", "%ld\n", OE_INT64_MIN));
    OE_TEST(_test("9223372036854775807\n", "%ld\n", OE_INT64_MAX));
    OE_TEST(_test("18446744073709551615\n", "%lu\n", OE_UINT64_MAX));

    OE_TEST(_test("-1\n", "%zd\n", OE_SIZE_MAX));
    OE_TEST(_test("18446744073709551615\n", "%zu\n", OE_SIZE_MAX));
    OE_TEST(_test("xxx=%%%%\n", "xxx=%%%%%%%%\n"));

    OE_TEST(_test(" 0\n", "% d\n", 0));
    OE_TEST(_test(" 0012345\n", "%0 8d\n", 12345));
    OE_TEST(_test("-12345\n", "% d\n", -12345));
    OE_TEST(_test("%i=87654321\n", "%%i=%i\n", 87654321));
    OE_TEST(_test("666\n", "%li\n", 666L));
    OE_TEST(_test("-1\n", "%zi\n", (size_t)-1));

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strstr(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    const char str[] = "abcdefghijklmnopqrstuvwxyz";
    const char* a = &str[0];
    const char* h = &str[7];
    const char* l = &str[11];
    const char* q = &str[16];
    const char* w = &str[22];
    const char* z = &str[25];

    OE_TEST(oe_strstr(str, "") == a);
    OE_TEST(oe_strstr(str, "abc") == a);
    OE_TEST(oe_strstr(str, "hijk") == h);
    OE_TEST(oe_strstr(str, "lmnop") == l);
    OE_TEST(oe_strstr(str, "qrstuv") == q);
    OE_TEST(oe_strstr(str, "wxyz") == w);
    OE_TEST(oe_strstr(str, "z") == z);
    OE_TEST(oe_strstr(str, "aaa") == NULL);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strlen(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    OE_TEST(oe_strlen("") == 0);
    OE_TEST(oe_strlen("1") == 1);
    OE_TEST(oe_strlen("12") == 2);
    OE_TEST(oe_strlen("123") == 3);
    OE_TEST(oe_strlen("1234") == 4);
    OE_TEST(oe_strlen("12345") == 5);
    OE_TEST(oe_strlen("123456") == 6);
    OE_TEST(oe_strlen("1234567") == 7);
    OE_TEST(oe_strlen("12345678") == 8);
    OE_TEST(oe_strlen("123456789") == 9);
    OE_TEST(oe_strnlen("123456789", 100) == 9);
    OE_TEST(oe_strnlen("123456789", 4) == 4);
    OE_TEST(oe_strnlen("123456789", 0) == 0);
    OE_TEST(oe_strnlen("", OE_SIZE_MAX) == 0);
    OE_TEST(oe_strnlen("a", OE_SIZE_MAX) == 1);
    OE_TEST(oe_strnlen("aa", OE_SIZE_MAX) == 2);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strchr(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    const char str[] = "abcdefghijklmnopqrstuvwxyz";
    const char* a = &str[0];
    const char* h = &str[7];
    const char* l = &str[11];
    const char* q = &str[16];
    const char* w = &str[22];
    const char* z = &str[25];
    const char* end = &str[26];

    OE_TEST(oe_strchr(str, 'a') == a);
    OE_TEST(oe_strchr(str, 'h') == h);
    OE_TEST(oe_strchr(str, 'l') == l);
    OE_TEST(oe_strchr(str, 'q') == q);
    OE_TEST(oe_strchr(str, 'w') == w);
    OE_TEST(oe_strchr(str, 'z') == z);
    OE_TEST(oe_strchr(str, 'A') == NULL);
    OE_TEST(oe_strchr(str, '\0') == end);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strncat(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    {
        char buf[16];
        *buf = '\0';
        oe_strncat(buf, "abcdefg", 4);
        OE_TEST(oe_strcmp(buf, "abcd") == 0);
        oe_strncat(buf, "efgxxx", 3);
        OE_TEST(oe_strcmp(buf, "abcdefg") == 0);
    }

    {
        char buf[8];
        *buf = '\0';
        oe_strncat(buf, "abcdefghijklmnop", 7);
        OE_TEST(oe_strcmp(buf, "abcdefg") == 0);
    }

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

static void _test_strerror(void)
{
    oe_printf("=== start %s()\n", __FUNCTION__);

    const char* s;

    OE_TEST((s = oe_strerror(OE_ENOMEM)));
    OE_TEST(oe_strcmp(s, "Cannot allocate memory") == 0);

    OE_TEST((s = oe_strerror(123456789)));
    OE_TEST(oe_strcmp(s, "Unknown error") == 0);

    oe_printf("=== passed %s()\n", __FUNCTION__);
}

OE_ECALL void test_isalnum(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isalnum(args->c);
}

OE_ECALL void test_isalpha(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isalpha(args->c);
}

OE_ECALL void test_iscntrl(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_iscntrl(args->c);
}

OE_ECALL void test_isdigit(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isdigit(args->c);
}

OE_ECALL void test_isgraph(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isgraph(args->c);
}

OE_ECALL void test_islower(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_islower(args->c);
}

OE_ECALL void test_isprint(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isprint(args->c);
}

OE_ECALL void test_ispunct(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_ispunct(args->c);
}

OE_ECALL void test_isspace(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isspace(args->c);
}

OE_ECALL void test_isupper(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isupper(args->c);
}

OE_ECALL void test_isxdigit(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_isxdigit(args->c);
}

OE_ECALL void test_tolower(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_tolower(args->c);
}

OE_ECALL void test_toupper(void* arg)
{
    ctype_args_t* args = (ctype_args_t*)arg;
    args->ret = oe_toupper(args->c);
}

OE_ECALL void test_enclave(void* args_)
{
    args_t* args = (args_t*)args_;

    _test_setjmp();
    _test_strdup();
    _test_strcasecmp();
    _test_oe_snprintf();
    _test_malloc();
    _test_strtoul();
    _test_strcpy();
    _test_printf();
    _test_strstr();
    _test_strlen();
    _test_strchr();
    _test_strncat();
    _test_strerror();

    args->ret = 0;
}
