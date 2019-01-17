// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_WINDOWS_H
#define _ELIBC_WINDOWS_H

#include "bits/common.h"

typedef unsigned int WORD;

typedef struct _SYSTEMTIME {
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
} SYSTEMTIME, *LPSYSTEMTIME;

void GetSystemTime(LPSYSTEMTIME lpSystemTime);

#endif /* _ELIBC_WINDOWS_H */
