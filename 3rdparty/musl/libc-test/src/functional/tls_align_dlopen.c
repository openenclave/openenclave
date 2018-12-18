#include <dlfcn.h>
#include "test.h"

int main()
{
	int i;
	void *h;
	struct {
		char *name;
		unsigned size;
		unsigned align;
		unsigned long addr;
	} *t;

	h = dlopen("src/functional/tls_align_dso.so", RTLD_LAZY);
	if (!h)
		t_error("dlopen failed\n");
	t = dlsym(h, "t");
	if (!t)
		t_error("dlsym failed\n");
	else for (i = 0; i < 4; i++) {
		if (!t[i].name)
			t_error("name is not set for t[%d]\n", i);
		if (t[i].addr & (t[i].align-1))
			t_error("bad alignment: %s, size: %u, align: %u, addr: 0x%lx\n",
				t[i].name, t[i].size, t[i].align, t[i].addr);
	}
	return t_status;
}
