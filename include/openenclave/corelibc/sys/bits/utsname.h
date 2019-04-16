// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define __OE_UTSNAME_FIELD_SIZE 65
char sysname[__OE_UTSNAME_FIELD_SIZE];
char nodename[__OE_UTSNAME_FIELD_SIZE];
char release[__OE_UTSNAME_FIELD_SIZE];
char version[__OE_UTSNAME_FIELD_SIZE];
char machine[__OE_UTSNAME_FIELD_SIZE];
#ifdef _GNU_SOURCE
char domainname[__OE_UTSNAME_FIELD_SIZE];
#else
char __domainname[__OE_UTSNAME_FIELD_SIZE];
#endif
