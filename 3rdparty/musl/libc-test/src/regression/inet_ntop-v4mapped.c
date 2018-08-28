// commit: 1cd417bdf10366d63cc875e285c6418709a58c17 2013-07-25
// inet_ntop should use ipv4 notation for v4mapped addresses
#include <string.h>
#include <arpa/inet.h>
#include "test.h"

int main(void)
{
	char *expect = "::ffff:192.168.0.1";
	char buf[100];
	char addr[16];
	if (inet_pton(AF_INET6, expect, addr) == 1) {
		if (!inet_ntop(AF_INET6, addr, buf, sizeof buf))
			t_error("inet_ntop failed\n");
		else if (!strchr(buf, '.'))
			t_error("inet_ntop produced %s instead of %s\n", buf, expect);
	} else {
		t_error("inet_pton failed\n");
	}
	return t_status;
}
