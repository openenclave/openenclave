#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <string.h>
#include "test.h"

#define N(s, tail, sub) { \
	char *p = s tail; \
	char *q = memmem(p, strlen(s), sub, strlen(sub)); \
	if (q) \
		t_error("memmem("#s" "#tail", %d, "#sub", %d) returned str+%d, wanted 0\n",\
			strlen(s), strlen(sub), q-p); \
}

#define T(s, sub, n) { \
	char *p = s; \
	char *q = memmem(p, strlen(p), sub, strlen(sub)); \
	if (q == 0) \
		t_error("memmem(%s,%s) returned 0, wanted str+%d\n", #s, #sub, n); \
	else if (q - p != n) \
		t_error("memmem(%s,%s) returned str+%d, wanted str+%d\n", #s, #sub, q-p, n); \
}

int main(void)
{
	N("","a", "a")
	N("a","a", "aa")
	N("a","b", "b")
	N("aa","b", "ab")
	N("aa","a", "aaa")
	N("aba","b", "bab")
	N("abba","b", "bab")
	N("abba","ba", "aba")
	N("abc abc","d", "abcd")
	N("0-1-2-3-4-5-6-7-8-9","", "-3-4-56-7-8-")
	N("0-1-2-3-4-5-6-7-8-9","", "-3-4-5+6-7-8-")
	N("_ _ _\xff_ _ _","\x7f_", "_\x7f_")
	N("_ _ _\x7f_ _ _","\xff_", "_\xff_")

	T("", "", 0)
	T("abcd", "", 0)
	T("abcd", "a", 0)
	T("abcd", "b", 1)
	T("abcd", "c", 2)
	T("abcd", "d", 3)
	T("abcd", "ab", 0)
	T("abcd", "bc", 1)
	T("abcd", "cd", 2)
	T("ababa", "baba", 1)
	T("ababab", "babab", 1)
	T("abababa", "bababa", 1)
	T("abababab", "bababab", 1)
	T("ababababa", "babababa", 1)
	T("abbababab", "bababa", 2)
	T("abbababab", "ababab", 3)
	T("abacabcabcab", "abcabcab", 4)
	T("nanabanabanana", "aba", 3)
	T("nanabanabanana", "ban", 4)
	T("nanabanabanana", "anab", 1)
	T("nanabanabanana", "banana", 8)
	T("_ _\xff_ _", "_\xff_", 2)

	return t_status;
}
