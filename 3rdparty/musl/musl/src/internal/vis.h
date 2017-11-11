/* This file is only used if enabled in the build system, in which case it is
 * included automatically via command line options. It is not included
 * explicitly by any source files or other headers. Its purpose is to
 * override default visibilities to reduce the size and performance costs
 * of position-independent code. */

#ifndef CRT
#ifdef SHARED

/* For shared libc.so, all symbols should be protected, but some toolchains
 * fail to support copy relocations for protected data, so exclude all
 * exported data symbols. */

__attribute__((__visibility__("default")))
extern int optind, opterr, optopt, optreset, __optreset, getdate_err, h_errno, daylight, __daylight, signgam, __signgam;

__attribute__((__visibility__("default")))
extern long timezone, __timezone;

__attribute__((__visibility__("default")))
extern char *optarg, **environ, **__environ, *tzname[2], *__tzname[2], *__progname, *__progname_full;

#pragma GCC visibility push(protected)

#elif defined(__PIC__)

/* If building static libc.a as position-independent code, try to make
 * everything hidden except possibly-undefined weak references. */

__attribute__((__visibility__("default")))
extern void (*const __init_array_start)(), (*const __init_array_end)(),
	(*const __fini_array_start)(), (*const __fini_array_end)();

#pragma GCC visibility push(hidden)

#endif
#endif
