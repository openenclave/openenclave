// dn_expand should accept empty name (single \0)
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <resolv.h>
#include "test.h"

int main(void)
{
	unsigned char packet[] = "";
	char name[] = "XX";
	int r;

	/* empty name in packet */
	r = dn_expand(packet, packet+1, packet, name, 1);
	if (r!=1)
		t_error("dn_expand(\"\", name, 1) returned %d, wanted 1\n", r);
	if (name[0])
		t_error("dn_expand(\"\", name, 1) failed: got \"%s\" name, wanted \"\"\n", name);

	return t_status;
}
