/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <gtest/gtest.h>

#ifdef _WIN32
#include <windows.h>
int GetFilePath(char* path, int size)
{
    int bytes = GetModuleFileNameA(NULL, path, size);
    if (bytes == 0)
        return -1;
    else
        return bytes;
}
#else
#define MAX_PATH 256
#define _chdir chdir
int GetFilePath(char* path, int size)
{
    int length;
    length = readlink("/proc/self/exe", path, size);
    if (length < 0) {
        perror("resolving symlink /proc/self/exe.");
        exit(1);
    }
    if (length >= size) {
        fprintf(stderr, "Path too long.\n");
        exit(1);
    }

    path[length] = '\0';
    return length;
}
#endif

int main(int argc, char** argv)
{
    char path[MAX_PATH];
    int len = GetFilePath(path, sizeof(path));
    if (len > 0) {
        // Strip filename portion to just get directory.
    }
    char* p = strrchr(path, '\\');
    if (p != NULL) {
        *p = 0;
    }
    printf("Setting current directory to %s\n", path);
    _chdir(path);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

