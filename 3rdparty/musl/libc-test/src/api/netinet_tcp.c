#include <netinet/tcp.h>
#define C(n) switch(n){case n:;}
static void f()
{
C(TCP_NODELAY)
}
