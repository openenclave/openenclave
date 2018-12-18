// decode across buffer boundary
#include <stdio.h>
#include <locale.h>
#include <wchar.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "test.h"

#define A(c) do { if (!(c)) t_error(#c" failed\n"); } while(0)

int main()
{
	t_setutf8();

	int p[2];
	A(pipe(p) == 0);
	A(write(p[1], "x\340\240", 3) == 3);
	A(dup2(p[0], 0) == 0);
	wint_t wc;
	wc = fgetwc(stdin);
	A(wc == 'x');
	A(write(p[1], "\200", 1) == 1);
	close(p[1]);

	wc = fgetwc(stdin);
	if (wc != 0x800)
		t_error("wanted 0x800, got 0x%x\n", (unsigned)wc);

	errno = 0;
	wc = fgetwc(stdin);
	if (wc != WEOF)
		t_error("wanted WEOF, got 0x%x\n", (unsigned)wc);
	if (errno != 0)
		t_error("wanted errno==0, got %d (%s)\n", errno, strerror(errno));
	A(feof(stdin)!=0);
	A(ferror(stdin)==0);
	return t_status;
}
