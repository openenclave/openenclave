// commit: 3e936ce81bbbcc968f576aedbd5203621839f152 2014-09-19
// flockfile linked list handling was broken
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

int main()
{
	FILE *f = tmpfile();
	FILE *g = tmpfile();
	flockfile(g);
	flockfile(f);
	funlockfile(g);
	fclose(g);

	/* fill memory */
	if (t_vmfill(0,0,0) < 0)
		t_error("vmfill failed: %s\n", strerror(errno));
	size_t i,n;
	unsigned char *p;
	for (n = 1; n < 10000; n++) {
		if (!(p=malloc(n))) break;
		free(p);
	}
	n--;
	if (!(p=malloc(n))) {
		t_error("bad malloc fragmentation\n");
		return t_status;
	}
	memset(p, 0xff, n);

	/* may corrupt memory */
	funlockfile(f);
	for (i=0; i<n; i++) {
		if (p[i]!=0xff) {
			t_error("p[%zu] = %.2x\n", i, p[i]);
		}
	}
	return t_status;
}
