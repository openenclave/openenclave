#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <unistd.h>
#include "test.h"

/* adapted from dietlibc's test-newfnmatch.c */

/* xlat / printflags adapted from http://www.liacs.nl/~wichert/strace/ */
#define FLAG(f) { f, #f }

struct xlat {
	int val;
	char *str;
} fnmatch_flags[] = {
	FLAG(FNM_NOESCAPE),
	FLAG(FNM_PATHNAME),
	FLAG(FNM_PERIOD),
#ifdef FNM_CASEFOLD
	FLAG(FNM_CASEFOLD),
#endif
	{0, NULL},
};

static char *flagstr(const struct xlat *map, int flags)
{
	static char buf[1000];
	char *sep;
	int n;

	if (!flags) {
		sprintf(buf, "0");
		return buf;
	}
	n = 0;
	sep = "";
	for (; map->str; map++) {
		if (map->val && (flags & map->val) == map->val) {
			n += sprintf(buf+n, "%s%s", sep, map->str);
			sep = "|";
			flags &= ~(map->val);
		}
	}
	if (flags)
		sprintf(buf, "%sunknown=%#x", sep, flags);
	return buf;
}

/* tests harness adapted from glibc testfnm.c */
struct {
	const char *pattern;
	const char *string;
	int flags;
	int expected;
} tests[] = {
	/* begin dietlibc tests */
	{ "*.c", "foo.c", 0, 0 },
	{ "*.c", ".c", 0, 0 },
	{ "*.a", "foo.c", 0, FNM_NOMATCH },
	{ "*.c", ".foo.c", 0, 0 },
	{ "*.c", ".foo.c", FNM_PERIOD, FNM_NOMATCH },
	{ "*.c", "foo.c", FNM_PERIOD, 0 },
	{ "a\\*.c", "a*.c", FNM_NOESCAPE, FNM_NOMATCH },
	{ "a\\*.c", "ax.c", 0, FNM_NOMATCH },
	{ "a[xy].c", "ax.c", 0, 0 },
	{ "a[!y].c", "ax.c", 0, 0 },
	{ "a[a/z]*.c", "a/x.c", FNM_PATHNAME, FNM_NOMATCH },
	{ "a/*.c", "a/x.c", FNM_PATHNAME, 0 },
	{ "a*.c", "a/x.c", FNM_PATHNAME, FNM_NOMATCH },
	{ "*/foo", "/foo", FNM_PATHNAME, 0 },
	{ "-O[01]", "-O1", 0, 0 },
	{ "[[?*\\]", "\\", 0, 0 },
	{ "[]?*\\]", "]", 0, 0 },
	/* initial right-bracket tests */
	{ "[!]a-]", "b", 0, 0 },
	{ "[]-_]", "^", 0, 0 }, /* range: ']', '^', '_' */
	{ "[!]-_]", "X", 0, 0 },
	{ "??", "-", 0, FNM_NOMATCH },
	/* begin glibc tests */
	{ "*LIB*", "lib", FNM_PERIOD, FNM_NOMATCH },
	{ "a[/]b", "a/b", 0, 0 },
	{ "a[/]b", "a/b", FNM_PATHNAME, FNM_NOMATCH },
	{ "[a-z]/[a-z]", "a/b", 0, 0 },
	{ "*", "a/b", FNM_PATHNAME, FNM_NOMATCH },
	{ "*[/]b", "a/b", FNM_PATHNAME, FNM_NOMATCH },
	{ "*[b]", "a/b", FNM_PATHNAME, FNM_NOMATCH },
	{ "[*]/b", "a/b", 0, FNM_NOMATCH },
	{ "[*]/b", "*/b", 0, 0 },
	{ "[?]/b", "a/b", 0, FNM_NOMATCH },
	{ "[?]/b", "?/b", 0, 0 },
	{ "[[a]/b", "a/b", 0, 0 },
	{ "[[a]/b", "[/b", 0, 0 },
	{ "\\*/b", "a/b", 0, FNM_NOMATCH },
	{ "\\*/b", "*/b", 0, 0 },
	{ "\\?/b", "a/b", 0, FNM_NOMATCH },
	{ "\\?/b", "?/b", 0, 0 },
	{ "[/b", "[/b", 0, 0 },
	{ "\\[/b", "[/b", 0, 0 },
	{ "??""/b", "aa/b", 0, 0 },
	{ "???b", "aa/b", 0, 0 },
	{ "???b", "aa/b", FNM_PATHNAME, FNM_NOMATCH },
	{ "?a/b", ".a/b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "a/?b", "a/.b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "*a/b", ".a/b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "a/*b", "a/.b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "[.]a/b", ".a/b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "a/[.]b", "a/.b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "*/?", "a/b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ "?/*", "a/b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ ".*/?", ".a/b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ "*/.?", "a/.b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ "*/*", "a/.b", FNM_PATHNAME|FNM_PERIOD, FNM_NOMATCH },
	{ "*?*/*", "a/.b", FNM_PERIOD, 0 },
	{ "*[.]/b", "a./b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ "*[[:alpha:]]/*[[:alnum:]]", "a/b", FNM_PATHNAME, 0 },
	/* These three tests should result in error according to SUSv3.
	 * See XCU 2.13.1, XBD 9.3.5, & fnmatch() */
	{ "*[![:digit:]]*/[![:d-d]", "a/b", FNM_PATHNAME, -FNM_NOMATCH },
	{ "*[![:digit:]]*/[[:d-d]", "a/[", FNM_PATHNAME, -FNM_NOMATCH },
	{ "*[![:digit:]]*/[![:d-d]", "a/[", FNM_PATHNAME, -FNM_NOMATCH },
	{ "a?b", "a.b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ "a*b", "a.b", FNM_PATHNAME|FNM_PERIOD, 0 },
	{ "a[.]b", "a.b", FNM_PATHNAME|FNM_PERIOD, 0 },

	/* posix 2008 is unclear about these cases */
	{ "\\", "\\", 0, 0 },
	{ "\\", "", 0, FNM_NOMATCH },

	/* musl bug fixed in da0fcdb8e913ca7cdf8931328f2b37e93309b2c5 */
	{ "/", "\0", FNM_PATHNAME, FNM_NOMATCH },
	/* musl bug fixed in 6ec82a3b58ee1b873ff0dfad8fa9d41c3d25dcc0 */
	{ "\\/", "/", FNM_PATHNAME, 0 },

#ifdef FNM_CASEFOLD
	{ "a", "A", FNM_CASEFOLD, 0 },
	{ "aaAA", "AaAa", FNM_CASEFOLD, 0 },
	{ "[a]", "A", FNM_CASEFOLD, 0 },
	{ "[!a]", "A", FNM_CASEFOLD, FNM_NOMATCH },
	{ "[!A-C]", "b", FNM_CASEFOLD, FNM_NOMATCH },
	{ "[!a-c]", "B", FNM_CASEFOLD, FNM_NOMATCH },
	{ "[!a-c]", "d", FNM_CASEFOLD, 0 },
#endif
};

int main(void)
{
	int i;

	for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
		int r, x;

		r = fnmatch(tests[i].pattern, tests[i].string, tests[i].flags);
		x = tests[i].expected;
		if (r != x && (r != FNM_NOMATCH || x != -FNM_NOMATCH)) {
			t_error("fnmatch(\"%s\", \"%s\", %s) failed, got %d want %d\n",
				tests[i].pattern, tests[i].string,
				flagstr(fnmatch_flags, tests[i].flags),
				r, x);
		}
	}
	return t_status;
}
