// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CRT_TYPES_H_
#define _OE_CRT_TYPES_H_

#define _CRTALLOC(x) __declspec(allocate(x))

typedef void(__cdecl* _PVFV)(void);
typedef int(__cdecl* _PIFV)(void);

#pragma section(".CRT$XCA", long, read)
#pragma section(".CRT$XCZ", long, read)
#pragma section(".CRT$XIA", long, read)
#pragma section(".CRT$XIZ", long, read)
#pragma section(".CRT$XPA", long, read)
#pragma section(".CRT$XPZ", long, read)
#pragma section(".CRT$XTA", long, read)
#pragma section(".CRT$XTZ", long, read)

#endif /* _OE_CRT_TYPES_H_ */
