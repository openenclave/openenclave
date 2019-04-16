// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/stdioex.h>
#include <stdio.h>

#if 0
OE_FILE *oe_fopen_dev(uint64_t devid, const char *path, const char *mode)
{
    oe_set_device_for_current_thread(device_id);
    OE_FILE* ret = (OE_FILE*)fopen(path, mode);
    oe_clear_device_for_current_thread();

    return ret;
}

size_t oe_fread(void *ptr, size_t size, size_t nmemb, OE_FILE *stream)
{
    return fread(ptr, size, nmemb, (FILE*)stream);
}

size_t oe_fwrite(const void *ptr, size_t size, size_t nmemb, OE_FILE *stream)
{
    return fwrite(ptr, size, nmemb, (FILE*)stream);
}

int oe_fseek(OE_FILE *stream, long offset, int whence)
{
    return fseek((FILE*)stream, offset, whence);
}

long oe_ftell(OE_FILE *stream)
{
    return ftell((FILE*)stream);
}

int oe_fputs(const char *s, OE_FILE *stream)
{
    return fputs(s, (FILE*)stream);
}

char *oe_fgets(char *s, int size, OE_FILE *stream)
{
    return fgets(s, size, (FILE*)stream);
}

int oe_feof(OE_FILE* stream)
{
    return feof((FILE*)stream);
}

int oe_ferror(OE_FILE *stream)
{
    return ferror((FILE*)stream);
}

int oe_fflush(OE_FILE *stream)
{
    return fflush((FILE*)stream);
}

int oe_fclose(OE_FILE* stream)
{
    return fclose((FILE*)stream);
}
#endif
