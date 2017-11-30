#include <netinet/in.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
#define I(t,e) {t x[sizeof(t)==sizeof(e)] = {e};}
static void f()
{
T(in_port_t)
T(in_addr_t)
T(sa_family_t)
T(uint8_t)
T(uint32_t)
{
struct in_addr x;
F(in_addr_t, s_addr)
}
{
struct sockaddr_in x;
F(sa_family_t, sin_family)
F(in_port_t, sin_port)
F(struct in_addr, sin_addr)
}
{
struct in6_addr x;
F(uint8_t, s6_addr[16])
}
{
struct sockaddr_in6 x;
F(sa_family_t, sin6_family)
F(in_port_t, sin6_port)
F(uint32_t, sin6_flowinfo)
F(struct in6_addr, sin6_addr)
F(uint32_t, sin6_scope_id)
}
{const struct in6_addr *x = &in6addr_any;}
{const struct in6_addr *x = &in6addr_loopback;}
{struct in6_addr x = IN6ADDR_ANY_INIT;}
{struct in6_addr x = IN6ADDR_LOOPBACK_INIT;}
{
struct ipv6_mreq x;
F(struct in6_addr, ipv6mr_multiaddr)
F(unsigned, ipv6mr_interface)
}
C(IPPROTO_IP)
C(IPPROTO_IPV6)
C(IPPROTO_ICMP)
C(IPPROTO_RAW)
C(IPPROTO_TCP)
C(IPPROTO_UDP)
C(INADDR_ANY)
C(INADDR_BROADCAST)
C(INET_ADDRSTRLEN)
I(uint32_t,htonl(0LL))
I(uint16_t,htons(0LL))
I(uint32_t,ntohl(0LL))
I(uint16_t,ntohs(0LL))
C(INET6_ADDRSTRLEN)
C(IPV6_JOIN_GROUP)
C(IPV6_LEAVE_GROUP)
C(IPV6_MULTICAST_HOPS)
C(IPV6_MULTICAST_IF)
C(IPV6_MULTICAST_LOOP)
C(IPV6_UNICAST_HOPS)
C(IPV6_V6ONLY)
I(int,IN6_IS_ADDR_UNSPECIFIED(&in6addr_any))
I(int,IN6_IS_ADDR_LOOPBACK(&in6addr_any))
I(int,IN6_IS_ADDR_MULTICAST(&in6addr_any))
I(int,IN6_IS_ADDR_LINKLOCAL(&in6addr_any))
I(int,IN6_IS_ADDR_SITELOCAL(&in6addr_any))
I(int,IN6_IS_ADDR_V4MAPPED(&in6addr_any))
I(int,IN6_IS_ADDR_V4COMPAT(&in6addr_any))
I(int,IN6_IS_ADDR_MC_NODELOCAL(&in6addr_any))
I(int,IN6_IS_ADDR_MC_LINKLOCAL(&in6addr_any))
I(int,IN6_IS_ADDR_MC_SITELOCAL(&in6addr_any))
I(int,IN6_IS_ADDR_MC_ORGLOCAL(&in6addr_any))
I(int,IN6_IS_ADDR_MC_GLOBAL(&in6addr_any))
}
