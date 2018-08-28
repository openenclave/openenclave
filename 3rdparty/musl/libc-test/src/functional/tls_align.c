#include "test.h"

extern struct {
	char *name;
	unsigned size;
	unsigned align;
	unsigned long addr;
} t[4];

int main()
{
	int i;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		if (!t[i].name)
			t_error("name is not set for t[%d]\n", i);
		if (t[i].addr & (t[i].align-1))
			t_error("bad alignment: %s, size: %u, align: %u, addr: 0x%lx\n",
				t[i].name, t[i].size, t[i].align, t[i].addr);
	}
	return t_status;
}
