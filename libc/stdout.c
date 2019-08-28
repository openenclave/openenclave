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

/*
**==============================================================================
**
** This definition was copied and modified from MUSL. The original stdout
** definition initializes the FILE.lock field to -1, which suppresses locking.
** The MUSL FLOCK macro is defined as follows:
**
**     #define FLOCK(f) int __need_unlock = ((f)->lock>=0 ? __lockfile((f)) : 0)
**
** Note that __lockfile is not called when FILE.lock is negative one. When
** multiple threads write to stdout or stderr, they eventually call the
** following function without acquiring a lock (via FLOCK).
**
**     size_t __fwritex(const unsigned char* s, size_t l, FILE* f);
**
** This function modifies the state of the file stream and sometimes crashes
** (segmentation violation) when called on the same stream by multiple threads.
**
**==============================================================================
*/

#include "stdio_impl.h"

#undef stdout

static unsigned char buf[BUFSIZ + UNGET];
hidden FILE __stdout_FILE = {
    .buf = buf + UNGET,
    .buf_size = sizeof buf - UNGET,
    .fd = 1,
    .flags = F_PERM | F_NORD,
    .lbf = '\n',
    .write = __stdout_write,
    .seek = __stdio_seek,
    .close = __stdio_close,
    /* OE: Changed from -1 to 0 to force locking. */
    .lock = 0,
};
FILE* const stdout = &__stdout_FILE;
FILE* volatile __stdout_used = &__stdout_FILE;
