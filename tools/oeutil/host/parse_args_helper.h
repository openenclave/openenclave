// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(_WIN32)
/* Use the ISO-conformant MSVC names to avoid C4996 deprecation errors */
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif
