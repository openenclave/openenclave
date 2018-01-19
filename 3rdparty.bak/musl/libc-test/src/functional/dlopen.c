#include <dlfcn.h>
#include "test.h"

int main(int argc, char *argv[])
{
	void *h, *g;
	int *i, *i2;
	char *s;
	void (*f)(void);
	char buf[512];

	if (!t_pathrel(buf, sizeof buf, argv[0], "dlopen_dso.so")) {
		t_error("failed to obtain relative path to dlopen_dso.so\n");
		return 1;
	}
	h = dlopen(buf, RTLD_LAZY|RTLD_LOCAL);
	if (!h)
		t_error("dlopen %s failed: %s\n", buf, dlerror());
	i = dlsym(h, "i");
	if (!i)
		t_error("dlsym i failed: %s\n", dlerror());
	if (*i != 1)
		t_error("initialization failed: want i=1 got i=%d\n", *i);
	f = (void (*)(void))dlsym(h, "f");
	if (!f)
		t_error("dlsym f failed: %s\n", dlerror());
	f();
	if (*i != 2)
		t_error("f call failed: want i=2 got i=%d\n", *i);

	g = dlopen(0, RTLD_LAZY|RTLD_LOCAL);
	if (!g)
		t_error("dlopen 0 failed: %s\n", dlerror());
	i2 = dlsym(g, "i");
	s = dlerror();
	if (i2 || s == 0)
		t_error("dlsym i should have failed\n");
	if (dlsym(g, "main") != (void*)main)
		t_error("dlsym main failed: %s\n", dlerror());

	/* close+open reinitializes the dso with glibc but not with musl */
	h = dlopen(buf, RTLD_LAZY|RTLD_GLOBAL);
	i2 = dlsym(g, "i");
	if (!i2)
		t_error("dlsym i failed: %s\n", dlerror());
	if (i2 != i)
		t_error("reopened dso should have the same symbols, want %p, got %p\n", i, i2);
	if (*i2 != 2)
		t_error("reopened dso should have the same symbols, want i2==2, got i2==%d\n", *i2);
	if (dlclose(g))
		t_error("dlclose failed: %s\n", dlerror());
	if (dlclose(h))
		t_error("dlclose failed: %s\n", dlerror());
	return t_status;
}
