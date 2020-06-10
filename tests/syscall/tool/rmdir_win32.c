// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <windows.h>

int recursive_rmdir(const wchar_t* path)
{
    int ret = -1;
    wchar_t* doublenullpath = NULL;
    int len = (int)wcslen(path);
    SHFILEOPSTRUCTW opt;

    // https://docs.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shfileopstructw
    // Here we need a path double-null terminated.
    // Since len does not include \0, alloc 2 extra besides len.
    doublenullpath = malloc((len + 2) * sizeof(wchar_t));
    if (!doublenullpath)
    {
        goto done;
    }
    memcpy(doublenullpath, path, len * sizeof(wchar_t));
    doublenullpath[len] = doublenullpath[len + 1] = L'\0';

    memset(&opt, 0, sizeof(SHFILEOPSTRUCTW));
    opt.pFrom = doublenullpath;
    opt.hwnd = NULL;
    opt.wFunc = FO_DELETE;
    opt.fFlags = FOF_SILENT | FOF_NOERRORUI | FOF_ALLOWUNDO |
                 FOF_NOCONFIRMMKDIR | FOF_NOCONFIRMATION;

    ret = SHFileOperationW(&opt);

done:
    free(doublenullpath);
    return ret;
}
