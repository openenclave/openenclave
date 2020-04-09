// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <windows.h>

#include <openenclave/internal/tests.h>
#include <shlwapi.h>

OE_EXTERNC_BEGIN
PCWSTR oe_syscall_path_to_win(const char* path);
OE_EXTERNC_END

#define VOLUME_PATH_PROXY L"<VOL>"
#define CURRENT_PATH_PROXY L"<CUR>"
#define PATH_PROXY_LENGTH 5

typedef struct _test
{
    const char* posix_path;
    PCWSTR win_path;
} test_t;

static bool _has_test_failed = false;

const test_t tests[] = {
    /* Test handling of explicit volume rooted paths */
    {"D:", L"D:\\"},
    {"D:\\", L"D:\\"},
    {"D:\\..", L"D:\\"},
    {"D:/..", L"D:\\"},
    {"D:\\\\.", L"D:\\"},
    {"D://.", L"D:\\"},
    {"/x", L"X:\\"},
    {"/x/", L"X:\\"},
    {"/x/rootfile.txt", L"X:\\rootfile.txt"},

    /* Test current volume rooted paths */
    {"\\", VOLUME_PATH_PROXY},
    {"/", VOLUME_PATH_PROXY},
    {"\\rootfile.txt", VOLUME_PATH_PROXY L"rootfile.txt"},
    {"/rootfile.txt", VOLUME_PATH_PROXY L"rootfile.txt"},

    /* Test Windows paths should not be interpreted as X:\ paths after
       canonicalization */
    {"D:\\..\\.\\x", L"D:\\x"},
    {"D:\\.\\..\\x\\", L"D:\\x\\"},
    {"D:/../x/.", L"D:\\x"},
    {"D:\\x\\..\\", L"D:\\"},
    {"D:/x/file.txt", L"D:\\x\\file.txt"},
    {"D:\\.\\x\\.\\file.txt", L"D:\\x\\file.txt"},

    /* Test converting relative paths to absolute paths */
    {".", CURRENT_PATH_PROXY},
    {"..", CURRENT_PATH_PROXY L".."},
    {"..\\..\\", CURRENT_PATH_PROXY L"..\\..\\"},
    {".././..", CURRENT_PATH_PROXY L"..\\.."},
    {"foo", CURRENT_PATH_PROXY L"foo"},
    {"foo\\bar", CURRENT_PATH_PROXY L"foo\\bar"},
    {"foo/bar/../baz/../../../foo/./bar/",
     CURRENT_PATH_PROXY L"..\\foo\\bar\\"},

    /* Test special handling of /dev/null */
    {"/dev/null", L"NUL"},
    {"\\dev\\null", L"C:\\dev\\null"},
    {"\\\\dev\\null", L"\\\\dev\\null"},
    /* NOTE: Linux will treat this as the null device still,
     * but OE chooses not to handle */
    {"/dev/./null", VOLUME_PATH_PROXY L"dev\\.\\null"},

    /* Test handling of a Unicode path */
    {"\xE2\x98\x83", CURRENT_PATH_PROXY L"\x2603"},
};

void _combine_paths(
    PWSTR result_path,
    uint32_t result_path_size,
    const wchar_t* root_path,
    const wchar_t* path)
{
    wchar_t combined_path[MAX_PATH] = {0};
    size_t root_path_length = wcsnlen(root_path, MAX_PATH);
    if (result_path_size <=
        wcsnlen(root_path, MAX_PATH) + wcsnlen(path, MAX_PATH))
    {
        fprintf(stderr, "Unexpected: Combined test paths > MAX_PATH");
        abort();
    }
    if (!PathCombineW(combined_path, root_path, path))
    {
        fprintf(stderr, "PathCombineW failed with %#x\n", GetLastError());
        abort();
    }
    else if (!PathCanonicalizeW(result_path, combined_path))
    {
        fprintf(stderr, "PathCanonicalizeW failed with %#x\n", GetLastError());
        abort();
    }
}

void _get_expected_path(
    const wchar_t* path,
    uint32_t path_length,
    wchar_t* expected_path_buffer,
    uint32_t expected_path_buffer_size)
{
    const uint32_t volume_path_length = 4;
    static wchar_t volume_path[volume_path_length] = {0};
    if (volume_path[0] == '\0' &&
        !GetVolumePathNameW(L".", volume_path, volume_path_length))
        printf("GetVolumePathNameW failed with %#x\n", GetLastError());

    static wchar_t current_path[MAX_PATH] = {0};
    if (current_path[0] == '\0')
    {
        DWORD current_path_length =
            GetCurrentDirectoryW(MAX_PATH, current_path);
        if (current_path_length == 0)
            printf("GetCurrentDirectoryW failed with %#x\n", GetLastError());
    }

    if (wcsstr(path, VOLUME_PATH_PROXY) == path)
    {
        _combine_paths(
            expected_path_buffer,
            expected_path_buffer_size,
            volume_path,
            path + PATH_PROXY_LENGTH);
    }
    else if (wcsstr(path, CURRENT_PATH_PROXY) == path)
    {
        _combine_paths(
            expected_path_buffer,
            expected_path_buffer_size,
            current_path,
            path + PATH_PROXY_LENGTH);
    }
    else
    {
        errno_t err = wcsncpy_s(
            expected_path_buffer, expected_path_buffer_size, path, path_length);
        if (err)
            printf("wcsncpy_n failed with %#x\n", err);
    }
}

inline void _test_path_to_win(const test_t* test)
{
    wchar_t expected_result[MAX_PATH] = {0};
    _get_expected_path(
        test->win_path,
        (uint32_t)wcslen(test->win_path),
        expected_result,
        MAX_PATH);
    PCWSTR test_result = oe_syscall_path_to_win(test->posix_path);

    if (0 == wcsncmp(expected_result, test_result, MAX_PATH))
        printf("[PASSED] ");
    else
    {
        printf("<FAILED> ");
        _has_test_failed = true;
    }

    printf(
        "Input: %s, Expect: %ls, Actual: %ls\n",
        test->posix_path,
        expected_result,
        test_result);

    if (test_result)
        free((void*)test_result);
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
