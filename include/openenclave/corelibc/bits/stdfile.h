// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_STDFILE_H
#define _OE_BITS_STDFILE_H

#define OE_BUFSIZ 8192
#define OE_EOF (-1)

typedef struct _OE_IO_FILE OE_FILE;
extern OE_FILE* const oe_stdin;
extern OE_FILE* const oe_stdout;
extern OE_FILE* const oe_stderr;

#if defined(OE_NEED_STDC_NAMES)
typedef OE_FILE FILE;
#define stdin oe_stdin
#define stdout oe_stdout
#define stderr oe_stderr
#endif

#endif /* _OE_BITS_STDFILE_H */
