// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_DUPENV_H
#define _OE_HOST_DUPENV_H

/* Return a copy of the named environment variable. The caller is responsible
 * for passing the returned value to free().
 */
char* oe_dupenv(const char* name);

#endif /* _OE_HOST_DUPENV_H */
