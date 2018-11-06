/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#undef errno
typedef int errno_t;

extern errno_t errno;

#define ERRNO

#define ENOENT     2
#define ENOMEM    12
#define EACCES    13
#define EEXIST    17
#define EINVAL    22
#define ERANGE    34
