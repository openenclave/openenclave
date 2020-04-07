// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <windows.h>

#include <openenclave/internal/tests.h>
#include <shlwapi.h>

OE_EXTERNC_BEGIN
char* oe_syscall_path_to_win(const char* path);
OE_EXTERNC_END

#define VOLUME_PATH_PROXY "<VOL>"
#define CURRENT_PATH_PROXY "<CUR>"
#define PATH_PROXY_LENGTH 5

typedef struct _test
{
    const char* posix_path;
    const char* win_path;
} test_t;

static bool _has_test_failed = false;

const test_t tests[] = {
    /* Test handling of explicit volume rooted paths */
    {"D:", "D:\\"},
    {"D:\\", "D:\\"},
    {"D:\\..", "D:\\"},
    {"D:/..", "D:\\"},
    {"D:\\\\.", "D:\\"},
    {"D://.", "D:\\"},
    {"/x", "X:\\"},
    {"/x/", "X:\\"},
    {"/x/rootfile.txt", "X:\\rootfile.txt"},

    /* Test current volume rooted paths */
    {"\\", VOLUME_PATH_PROXY},
    {"/", VOLUME_PATH_PROXY},
    {"\\rootfile.txt", VOLUME_PATH_PROXY "rootfile.txt"},
    {"/rootfile.txt", VOLUME_PATH_PROXY "rootfile.txt"},

    /* Test Windows paths should not be interpreted as X:\ paths after
       canonicalization */
    {"D:\\..\\.\\x", "D:\\x"},
    {"D:\\.\\..\\x\\", "D:\\x\\"},
    {"D:/../x/.", "D:\\x"},
    {"D:\\x\\..\\", "D:\\"},
    {"D:/x/file.txt", "D:\\x\\file.txt"},
    {"D:\\.\\x\\.\\file.txt", "D:\\x\\file.txt"},

    /* Test converting relative paths to absolute paths */
    {".", CURRENT_PATH_PROXY},
    {"..", CURRENT_PATH_PROXY ".."},
    {"..\\..\\", CURRENT_PATH_PROXY "..\\..\\"},
    {".././..", CURRENT_PATH_PROXY "..\\.."},
    {"foo", CURRENT_PATH_PROXY "foo"},
    {"foo\\bar", CURRENT_PATH_PROXY "foo\\bar"},
    {"foo/bar/../baz/../../../foo/./bar/", CURRENT_PATH_PROXY "..\\foo\\bar\\"},

    /* Test special handling of /dev/null */
    {"/dev/null", "NUL"},
    {"\\dev\\null", "C:\\dev\\null"},
    {"\\\\dev\\null", "\\\\dev\\null"},
    /* NOTE: Linux will treat this as the null device still,
     * but OE chooses not to handle */
    {"/dev/./null", VOLUME_PATH_PROXY "dev\\.\\null"},
};

void _combine_paths(
    char* result_path,
    uint32_t result_path_size,
    const char* root_path,
    const char* path)
{
    char combined_path[MAX_PATH] = {0};
    size_t root_path_length = strnlen(root_path, MAX_PATH);
    if (result_path_size <=
        strnlen(root_path, MAX_PATH) + strnlen(path, MAX_PATH))
    {
        fprintf(stderr, "Unexpected: Combined test paths > MAX_PATH");
        abort();
    }
    if (!PathCombineA(combined_path, root_path, path))
    {
        fprintf(stderr, "PathCombineA failed with %#x\n", GetLastError());
        abort();
    }
    else if (!PathCanonicalizeA(result_path, combined_path))
    {
        fprintf(stderr, "PathCanonicalizeA failed with %#x\n", GetLastError());
        abort();
    }
}

void _get_expected_path(
    const char* path,
    uint32_t path_length,
    char* expected_path_buffer,
    uint32_t expected_path_buffer_size)
{
    const uint32_t volume_path_length = 4;
    static char volume_path[volume_path_length] = {0};
    if (volume_path[0] == '\0' &&
        !GetVolumePathNameA(".", volume_path, volume_path_length))
        printf("GetVolumePathNameA failed with %#x\n", GetLastError());

    static char current_path[MAX_PATH] = {0};
    if (current_path[0] == '\0')
    {
        DWORD current_path_length = GetCurrentDirectory(MAX_PATH, current_path);
        if (current_path_length == 0)
            printf("GetCurrentDirectory failed with %#x\n", GetLastError());
    }

    if (strstr(path, VOLUME_PATH_PROXY) == path)
    {
        _combine_paths(
            expected_path_buffer,
            expected_path_buffer_size,
            volume_path,
            path + PATH_PROXY_LENGTH);
    }
    else if (strstr(path, CURRENT_PATH_PROXY) == path)
    {
        _combine_paths(
            expected_path_buffer,
            expected_path_buffer_size,
            current_path,
            path + PATH_PROXY_LENGTH);
    }
    else
    {
        errno_t err = strncpy_s(
            expected_path_buffer, expected_path_buffer_size, path, path_length);
        if (err)
            printf("strncpy_n failed with %#x\n", err);
    }
}

inline void _test_path_to_win(const test_t* test)
{
    char expected_result[MAX_PATH] = {0};
    _get_expected_path(
        test->win_path,
        (uint32_t)strlen(test->win_path),
        expected_result,
        MAX_PATH);
    char* test_result = oe_syscall_path_to_win(test->posix_path);

    if (0 == strncmp(expected_result, test_result, MAX_PATH))
        printf("[PASSED] ");
    else
    {
        printf("<FAILED> ");
        _has_test_failed = true;
    }

    printf(
        "Input: %s, Expect: %s, Actual: %s\n",
        test->posix_path,
        expected_result,
        test_result);

    if (test_result)
        free(test_result);
}

int main()
{
    uint32_t test_count = sizeof(tests) / sizeof(*tests);
    printf("Number of tests: %d\n", test_count);

    for (uint32_t i = 0; i < test_count; i++)
    {
        _test_path_to_win(&tests[i]);
    }

    return _has_test_failed ? -1 : 0;
}
