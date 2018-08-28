// zero compression for the last field in an ipv6 address is (probably) allowed
// https://tools.ietf.org/html/rfc4291#section-2.2
// but further fields shouldnt buffer overflow
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "test.h"

static void txt(char *s, unsigned char *buf)
{
	int i;
	sprintf(s, "%04x", buf[0]<<8 | buf[1]);
	for (i=1; i<8; i++)
		sprintf(s+5*i, ":%04x", buf[2*i]<<8 | buf[2*i+1]);
}

int main(void)
{
	char s[50], sw[50];
	unsigned char buf[16];
	unsigned char want[16] = {0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,0};
	char *addr;

	addr = "1:2:3:4:5:6:7::";
	if (inet_pton(AF_INET6, addr, buf)!=1 || memcmp(buf, want, 16)!=0) {
		txt(s, buf);
		txt(sw, want);
		t_error("inet_pton(%s) returned %s, wanted %s\n",
			addr, s, sw);
	}

	addr = "1:2:3:4:5:6:7::9:10:11:12:13:14:15:16:17:18:19:20";
	if (inet_pton(AF_INET6, addr, buf)!=0) {
		txt(s, buf);
		t_error("inet_pton(%s) returned %s, wanted a failure\n",
			addr, s);
	}
	return t_status;
}
