#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <fcntl.h>
#include "test.h"

#define TEST(c, ...) ((c) ? 1 : (t_error(#c" failed: " __VA_ARGS__),0))
#define TESTE(c) (errno=0, TEST(c, "errno = %s\n", strerror(errno)))

int main(void)
{
	struct sockaddr_in sa = { .sin_family = AF_INET };
	int s, c, t;
	char buf[100];

	TESTE((s=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP))>=0);
	TESTE(bind(s, (void *)&sa, sizeof sa)==0);
	TESTE(getsockname(s, (void *)&sa, (socklen_t[]){sizeof sa})==0);

	TESTE(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
		&(struct timeval){.tv_usec=1}, sizeof(struct timeval))==0);

	TESTE((c=socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP))>=0);
	sa.sin_addr.s_addr = htonl(0x7f000001);
	TESTE(sendto(c, "x", 1, 0, (void *)&sa, sizeof sa)==1);
	TESTE(recvfrom(s, buf, sizeof buf, 0, (void *)&sa, (socklen_t[]){sizeof sa})==1);
	TEST(buf[0]=='x', "'%c'\n", buf[0]);

	close(c);
	close(s);

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	TESTE((s=socket(PF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP))>=0);
	TEST(fcntl(s, F_GETFD)&FD_CLOEXEC, "SOCK_CLOEXEC did not work\n");
	TESTE(bind(s, (void *)&sa, sizeof sa)==0);
	TESTE(getsockname(s, (void *)&sa, (socklen_t[]){sizeof sa})==0);
	sa.sin_addr.s_addr = htonl(0x7f000001);

	TESTE(listen(s, 1)==0);

	TESTE((c=socket(PF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP))>=0);
	TEST(fcntl(c, F_GETFL)&O_NONBLOCK, "SOCK_NONBLOCK did not work\n");

	TESTE(connect(c, (void *)&sa, sizeof sa)==0 || errno==EINPROGRESS);

	TESTE((t=accept(s, (void *)&sa, &(socklen_t){sizeof sa}))>=0);

	close(t);
	close(c);
	close(s);

	return t_status;
}
