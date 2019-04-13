// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

void *__stack_chk_guard = (void *)0x00000aff;

void __attribute__((noreturn)) __stack_chk_fail(void);

void __stack_chk_fail(void)
{
	while (1)
		;
}
