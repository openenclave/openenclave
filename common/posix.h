// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_POSIX_H
#define _OE_COMMON_POSIX_H

#define OE_POSIX_OCALL_FUNCTION_TABLE_ID 0
#define OE_POSIX_ECALL_FUNCTION_TABLE_ID 0

/* Register the OCALL table needed by the POSIX interface (host). */
void oe_register_posix_ocall_function_table(void);

#endif /* _OE_COMMON_POSIX_H */
