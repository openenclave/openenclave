/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "gtest/gtest.h"

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
int GetFilePath(char* path, int size)
{
    char szTmp[32];
    sprintf(szTmp, "/proc/%d/exe", getpid());
    int bytes = MIN(readlink(szTmp, pBuf, len), len - 1);
    if (bytes >= 0)
    pBuf[bytes] = '\0';
    return bytes;
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

