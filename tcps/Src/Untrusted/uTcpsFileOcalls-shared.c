/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef LINUX

#include "sal_unsup.h"
#include "stdext.h"

#define _mkdir(x) mkdir((x), S_IRUSR | S_IWUSR)
#define _stat stat
#else

#include <direct.h>

#endif

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include "tcps_u.h"
#include "TcpsCalls_u.h"

int 
SGX_CDECL
ocall_mkdir(buffer256 dirname)
{
    int crtError;
    char *separator;
    char localPath[256];
    size_t length;
    char *currentName;
    char *nullTerminator;

    crtError = 0;

Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocall_mkdir");

    length = strlen(dirname.buffer) + 1;

    if (length > sizeof(localPath)) {
        crtError = ENAMETOOLONG;
        Tcps_GotoErrorWithStatus(crtError);
    }

    memcpy(localPath, dirname.buffer, length);
    nullTerminator = &localPath[length - 1];
    currentName = localPath;

    Tcps_Trace(Tcps_TraceLevelDebug, "ocall_mkdir: full path (%s)\n", localPath);

    for (;;) {
        if (currentName >= nullTerminator) {
            /* Success */
            return crtError;
        }

        separator = strchr(currentName, '/');

        if (separator != NULL) {
            *separator = 0;
        }

        if (separator != currentName) {
            if (_mkdir(localPath) != 0) {
                crtError = errno;

                // DMFIX - ignore EACCES because current user might not have access to the root directory.
                if ((crtError != EEXIST) && (crtError != EACCES)) {
                    Tcps_Trace(Tcps_TraceLevelDebug, "ocall_mkdir(%s): unexpected CRT error %d\n", localPath, errno);

                    Tcps_GotoErrorWithStatus(Tcps_Bad);
                }

                crtError = 0;
            } else {
                Tcps_Trace(Tcps_TraceLevelDebug, "ocall_mkdir: \"%s\" created\n", localPath);
            }
        }

        if (separator == NULL) {
            /* Success */
            return crtError;
        }

        *separator = '/';
        currentName = separator + 1;
    }

Tcps_BeginErrorHandling

    return crtError;
}

unsigned int
SGX_CDECL
ocall_ExportFile(
    buffer256 filename, 
    unsigned int appendToExistingFile, 
    buffer4096 ptr, 
    size_t len)
{
    FILE *fp = NULL;

    Tcps_InitializeStatus(Tcps_Module_Helper_u, "ExportFile");

    Tcps_Trace(
        Tcps_TraceLevelDebug, 
        "ExportFile: append = %u, size = %#x, file %s\n", 
        appendToExistingFile,
        len,
        filename.buffer);

    if (appendToExistingFile) {
        fopen_s(&fp, filename.buffer, "ab");
    } else {
        fopen_s(&fp, filename.buffer, "wb");
    }


    Tcps_GotoErrorIfTrue(fp == NULL, Tcps_BadInvalidArgument);
    Tcps_GotoErrorIfTrue(fwrite(ptr.buffer, 1, len, fp) != len, Tcps_Bad);

    fclose(fp);

    Tcps_ReturnStatusCode

Tcps_BeginErrorHandling

    if (fp != NULL) {
        fclose(fp);
    }

Tcps_FinishErrorHandling
}

GetUntrustedFileSize_Result
SGX_CDECL
ocall_GetUntrustedFileSize(
    buffer256 filename)
{
    GetUntrustedFileSize_Result result;
    struct _stat st;
    Tcps_StatusCode uStatus = Tcps_Good;

    Tcps_Trace(Tcps_TraceLevelDebug, "file (%s)\n", filename.buffer);

    if (_stat(filename.buffer, &st) < 0) {
        result.status = Tcps_BadInvalidArgument;
    } else {
        result.fileSize = st.st_size;

        Tcps_Trace(Tcps_TraceLevelDebug, "file (%s) -> size = %d\n", filename.buffer, result.fileSize);
    }
    result.status = uStatus;
    return result;
}

GetUntrustedFileContent_Result
SGX_CDECL
ocall_GetUntrustedFileContent(
    buffer256 filename, 
    size_t len)
{
    GetUntrustedFileContent_Result result;
    FILE *fp = NULL;
    Tcps_StatusCode uStatus = Tcps_Good;

    fopen_s(&fp, filename.buffer, "rb");

    Tcps_GotoErrorIfTrue(fp == NULL, Tcps_BadInvalidArgument);

    size_t cumul = 0;
    size_t current = 0;
    char* p = result.content;

    for (;;) {
        current = fread(p + cumul, 1, len - cumul, fp);
        if (current <= 0) {
            break;
        }
        cumul += current;
    }

    Tcps_GotoErrorIfTrue(cumul != len, Tcps_BadInvalidArgument);

Error:
    if (fp != NULL) {
        fclose(fp);
    }
    result.status = uStatus;
    return result;
}

int
SGX_CDECL
ocallTcpsFileDelete(
    buffer256 a_filename)
{
    Tcps_InitializeStatus(Tcps_Module_Helper_u, "ocallTcpsFileDelete");

    Tcps_GotoErrorIfTrue((remove(a_filename.buffer) != 0), Tcps_Bad);

Tcps_BeginErrorHandling

Tcps_FinishErrorHandling
}
