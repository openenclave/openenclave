#include <arpa/inet.h>
#define T(t) (t*)0;
#define C(n) switch(n){case n:;}
#define I(t,e) {t x[sizeof(t)==sizeof(e)] = {e};}
static void f()
{
T(in_port_t)
T(in_addr_t)
T(struct in_addr)
T(uint32_t)
T(uint16_t)

C(INET_ADDRSTRLEN)
C(INET6_ADDRSTRLEN)

#ifdef htonl
I(uint32_t, htonl(0LL))
#else
{uint32_t(*p)(uint32_t) = htonl;}
#endif
#ifdef htons
I(uint16_t, htons(0LL))
#else
{uint16_t(*p)(uint16_t) = htons;}
#endif
#ifdef ntohl
I(uint32_t, ntohl(0LL))
#else
{uint32_t(*p)(uint32_t) = ntohl;}
#endif
#ifdef ntohs
I(uint16_t, ntohs(0LL))
#else
{uint16_t(*p)(uint16_t) = ntohs;}
#endif

{in_addr_t(*p)(const char*) = inet_addr;}
{char*(*p)(struct in_addr) = inet_ntoa;}
{const char*(*p)(int,const void*restrict,char*restrict,socklen_t) = inet_ntop;}
{int(*p)(int,const char*restrict,void*restrict) = inet_pton;}
}
