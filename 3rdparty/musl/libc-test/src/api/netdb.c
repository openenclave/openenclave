#include <netdb.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(uint32_t)
T(socklen_t)
C(IPPORT_RESERVED)
{
struct hostent x;
F(char*, h_name)
F(char**, h_aliases)
F(int, h_addrtype)
F(int, h_length)
F(char**, h_addr_list)
}
{
struct netent x;
F(char*, n_name)
F(char**, n_aliases)
F(int, n_addrtype)
F(uint32_t, n_net)
}
{
struct protoent x;
F(char*, p_name)
F(char**, p_aliases)
F(int, p_proto)
}
{
struct servent x;
F(char*, s_name)
F(char**, s_aliases)
F(int, s_port)
F(char*, s_proto)
}
{
struct addrinfo x;
F(int, ai_flags)
F(int, ai_family)
F(int, ai_socktype)
F(int, ai_protocol)
F(socklen_t, ai_addrlen)
F(struct sockaddr*, ai_addr)
F(char*, ai_canonname)
F(struct addrinfo*, ai_next)
}
C(AI_PASSIVE)
C(AI_CANONNAME)
C(AI_NUMERICHOST)
C(AI_NUMERICSERV)
C(AI_V4MAPPED)
C(AI_ALL)
C(AI_ADDRCONFIG)
C(NI_NOFQDN)
C(NI_NUMERICHOST)
C(NI_NAMEREQD)
C(NI_NUMERICSERV)
C(NI_NUMERICSCOPE)
C(NI_DGRAM)
C(EAI_AGAIN)
C(EAI_BADFLAGS)
C(EAI_FAIL)
C(EAI_FAMILY)
C(EAI_MEMORY)
C(EAI_NONAME)
C(EAI_SERVICE)
C(EAI_SOCKTYPE)
C(EAI_SYSTEM)
C(EAI_OVERFLOW)
{void(*p)(void) = endhostent;}
{void(*p)(void) = endnetent;}
{void(*p)(void) = endprotoent;}
{void(*p)(void) = endservent;}
{const char*(*p)(int) = gai_strerror;}
{struct hostent*(*p)(void) = gethostent;}
{struct netent*(*p)(uint32_t,int) = getnetbyaddr;}
{struct netent*(*p)(const char*) = getnetbyname;}
{struct netent*(*p)(void) = getnetent;}
{struct protoent*(*p)(const char*) = getprotobyname;}
{struct protoent*(*p)(int) = getprotobynumber;}
{struct protoent*(*p)(void) = getprotoent;}
{struct servent*(*p)(const char*,const char*) = getservbyname;}
{struct servent*(*p)(int,const char*) = getservbyport;}
{struct servent*(*p)(void) = getservent;}
{void(*p)(int) = sethostent;}
{void(*p)(int) = setnetent;}
{void(*p)(int) = setprotoent;}
{void(*p)(int) = setservent;}
}
#include <sys/socket.h>
static void g()
{
{void(*p)(struct addrinfo*) = freeaddrinfo;}
{int(*p)(const char*restrict,const char*restrict,const struct addrinfo*restrict,struct addrinfo**restrict) = getaddrinfo;}
{int(*p)(const struct sockaddr*restrict,socklen_t,char*restrict,socklen_t,char*restrict,socklen_t,int) = getnameinfo;}
}
