#ifndef _OE_ATEXIT_H
#define _OE_ATEXIT_H

#include <openenclave/defs.h>

OE_EXTERNC_BEGIN

int OE_AtExit(void (*function)(void));

void OE_CallAtExitFunctions(void);

OE_EXTERNC_END

#endif /* _OE_ATEXIT_H */
