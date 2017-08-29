#ifndef _OE_RANDOM_H
#define _OE_RANDOM_H

#include "../common/defs.h"

/* Generate rand number using the RDRAND instruction */
unsigned long OE_Random(void);

#endif /* _OE_RANDOM_H */
