// dn_expand should handle offset pointer to 0 byte
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <resolv.h>
#include <string.h>
#include "test.h"

int main(void)
{
	unsigned char packet[] = {2,'p','q',0xc0,5,0};
	char name[] = "XXXX";
	int r;

	/* non-empty name with pointer to 0 */
	r = dn_expand(packet, packet+6, packet, name, 3);
	if (r!=5)
		t_error("dn_expand(\"\\2pq\\xc0\\5\", name, 3) returned %d, wanted 5\n", r);
	if (strcmp(name, "pq"))
		t_error("dn_expand(\"\\2pq\\xc0\\5\", name, 3) failed: got \"%s\" name, wanted \"pq\"\n", name);

	/* empty name with pointer to 0 */
	memcpy(packet, "\xc0\2", 3);
	memcpy(name, "XXXX", 5);
	r = dn_expand(packet, packet+3, packet, name, 1);
	if (r!=2)
		t_error("dn_expand(\"\\xc0\\2\", name, 1) returned %d, wanted 2\n", r);
	if (name[0])
		t_error("dn_expand(\"\\xc0\\2\", name, 1) failed: got \"%s\" name, wanted \"\"\n", name);

	return t_status;
}
