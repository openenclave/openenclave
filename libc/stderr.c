/*
** musl as a whole is licensed under the following standard MIT license:
**
** ----------------------------------------------------------------------
** Copyright © 2005-2014 Rich Felker, et al.
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
** ----------------------------------------------------------------------
*/

#include "stdio_impl.h"

#undef stderr

static unsigned char buf[UNGET];
hidden FILE __stderr_FILE = {
    .buf = buf + UNGET,
    .buf_size = 0,
    .fd = 2,
    .flags = F_PERM | F_NORD,
    .lbf = -1,
    .write = __stdio_write,
    .seek = __stdio_seek,
    .close = __stdio_close,
    /* OE: Changed from -1 to 0 to force locking. See note in stdout.c */
    .lock = 0,
};

FILE* const stderr = &__stderr_FILE;

FILE* volatile __stderr_used = &__stderr_FILE;
