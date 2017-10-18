#ifndef OE_INIT_H
#define OE_INIT_H

#include <openenclave/enclave.h>
#include "td.h"

void OE_CallConstructors(void);

void OE_InitializeEnclave(TD* td);

#endif /* OE_INIT_H */
