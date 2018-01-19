#include <iso646.h>
#define C(n) switch(n){case n:;}
static void f(){
int i = 0;
i and_eq 1;
i or_eq 1;
i xor_eq 1;
C(0 not_eq 1)
C(0 and 1)
C(0 or 1)
C(0 bitand 1)
C(0 bitor 1)
C(0 xor 1)
C(not 0)
C(compl 0)
}
