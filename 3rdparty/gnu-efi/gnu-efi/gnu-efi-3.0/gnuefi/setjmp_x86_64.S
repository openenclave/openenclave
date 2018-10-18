/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define EXT_C(sym) sym
#define FUNCTION(x)     .globl EXT_C(x) ; .type EXT_C(x), @function ; EXT_C(x):

	.file	"setjmp.S"

	.text

/*
 * int setjmp (jmp_buf env)
 */
FUNCTION(setjmp)
	pop	%rsi		/* Return address, and adjust the stack */
	xor	%rax, %rax
	movq	%rbx, 0(%rdi)	/* RBX */
	movq	%rsp, 8(%rdi)   /* RSP */
	push	%rsi
	movq	%rbp, 16(%rdi)	/* RBP */
	movq	%r12, 24(%rdi)	/* R12 */
	movq	%r13, 32(%rdi)	/* R13 */
	movq	%r14, 40(%rdi)	/* R14 */
	movq	%r15, 48(%rdi)	/* R15 */
	movq	%rsi, 56(%rdi)	/* RSI */
	ret

/*
 * int longjmp (jmp_buf env, int val)
 */
FUNCTION(longjmp)
	movl	%esi, %eax
	movq	(%rdi), %rbx
	movq	8(%rdi), %rsp
	movq	16(%rdi), %rbp
	movq	24(%rdi), %r12
	movq    32(%rdi), %r13
	movq    40(%rdi), %r14
	movq    48(%rdi), %r15
	jmp	*56(%rdi)

