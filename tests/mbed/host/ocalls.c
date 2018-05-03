
#define OE_TRACE_LEVEL 1

#include <dirent.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct _FileArgs
{
    FILE* F_ptr;
    char* path;
    char* mode;
    char* buf;
    void* ptr;
    int ret;

    long int li_var;
    int i_var;
    int len;

} F_Args;

OE_OCALL void OE_FOpen(void* FileArgs)
{
    FILE* fp;
    F_Args* args = (F_Args*)FileArgs;

    OE_TRACE_INFO("#### %s ###########\n", args->path);

    fp = fopen(args->path, args->mode);
    if (fp == NULL)
        printf("fopen error");
    else
    {
        OE_TRACE_INFO("\n file opened address fp =%p &&&&&&&&&\n", fp);
        args->F_ptr = fp;
    }
    return;
}

OE_OCALL void OE_FClose(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fclose(args->F_ptr);

    OE_TRACE_INFO("\n fclose Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FEof(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = feof(args->F_ptr);

    OE_TRACE_INFO("\n feof Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FError(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = ferror(args->F_ptr);

    OE_TRACE_INFO("\n ferror Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FGets(void* FileArgs)
{
    char* ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fgets(args->buf, args->len, args->F_ptr);

    OE_TRACE_INFO("\n fgets Ret = %d --- buf: %s \n", ret, args->buf);
    args->ptr = (void*)ret;
    return;
}

OE_OCALL void OE_FRead(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fread(args->buf, args->len, (size_t)args->i_var, args->F_ptr);

    OE_TRACE_INFO("\n fread Ret = %d --- buf: %s \n", ret, args->buf);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FWrite(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fwrite(args->buf, args->len, (size_t)args->i_var, args->F_ptr);

    OE_TRACE_INFO("\n fwrite Ret = %d --- buf: %s \n", ret, args->buf);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FSeek(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fseek(args->F_ptr, args->li_var, args->i_var);

    OE_TRACE_INFO("\n fseek Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FPutc(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fputc(args->i_var, args->F_ptr);

    OE_TRACE_INFO("\n fputc Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FTell(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = ftell(args->F_ptr);

    OE_TRACE_INFO("\n ftell Ret = %d --- \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_Opendir(void* FileArgs)
{
    F_Args* args = (F_Args*)FileArgs;

    args->ptr = (void*)opendir(args->path);

    OE_TRACE_INFO("\n opendir Ret = %d --- buf: %s \n", ret, args->buf);
    return;
}

OE_OCALL void OE_Closedir(void* FileArgs)
{
    F_Args* args = (F_Args*)FileArgs;

    args->ret = closedir((DIR*)args->ptr);

    OE_TRACE_INFO("\n closedir Ret = %d --- buf: %s \n", ret, args->buf);
    return;
}

OE_OCALL void OE_Readdir(void* FileArgs)
{
    F_Args* args = (F_Args*)FileArgs;

    args->ptr = (void*)readdir((DIR*)args->ptr);

    OE_TRACE_INFO("\n readdir Ret = %d --- buf: %s \n", ret, args->buf);
    return;
}

OE_OCALL void OE_Stat(void* FileArgs)
{
    F_Args* args = (F_Args*)FileArgs;

    args->ret = (int)stat(args->path, (struct stat*)args->ptr);

    OE_TRACE_INFO("\n stat  Ret = %d --- buf: %s \n", args->ret);
    return;
}
