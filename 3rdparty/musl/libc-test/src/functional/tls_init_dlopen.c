#include <string.h>
#include <dlfcn.h>
#include "test.h"

int main()
{
	void *h;
	char *(*f)(void);
	char *s;

	h = dlopen("src/functional/tls_init_dso.so", RTLD_NOW|RTLD_GLOBAL);
	if (!h)
		t_error("dlopen failed: %s\n", dlerror());
	f = dlsym(h, "gettls");
	if (!f)
		t_error("dlsym failed: %s\n", dlerror());
	s = f();
	if (!s)
		t_error("tls was not initialized at dlopen\n");
	if (strcmp(s, "foobar")!=0)
		t_error("tls was not initialized correctly at dlopen (got \"%s\", want \"foobar\"\n", s);

	return t_status;
}
