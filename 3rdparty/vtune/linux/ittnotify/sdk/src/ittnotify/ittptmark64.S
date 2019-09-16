/* <copyright>
  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright (c) 2005-2018 Intel Corporation. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
  The full GNU General Public License is included in this distribution
  in the file called LICENSE.GPL.

  Contact Information:
  http://software.intel.com/en-us/articles/intel-vtune-amplifier-xe/

  BSD LICENSE

  Copyright (c) 2005-2018 Intel Corporation. All rights reserved.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
</copyright> */

        .text
        .align  16
        .globl  __itt_pt_mark
        .globl  __itt_pt_event
        .globl  __itt_pt_mark_event
        .globl  __itt_pt_mark_threshold

/// void __itt_pt_mark(unsigned char index);
__itt_pt_mark:
__itt_pt_mark_int:
        and     $0xf, %rdi
        call    __itt_pt_mark_pic
__itt_pt_mark_pic:
        popq    %rax
        lea     (__itt_pt_mark_call_table - __itt_pt_mark_pic) (%rax,%rdi,4), %rdi
        jmp     *%rdi
        .long   0xfadefade
__itt_pt_mark_call_table:
        retq
        retq    $0x0
        retq
        retq    $0x1
        retq
        retq    $0x2
        retq
        retq    $0x3
        retq
        retq    $0x4
        retq
        retq    $0x5
        retq
        retq    $0x6
        retq
        retq    $0x7
        retq
        retq    $0x8
        retq
        retq    $0x9
        retq
        retq    $0xa
        retq
        retq    $0xb
        retq
        retq    $0xc
        retq
        retq    $0xd
        retq
        retq    $0xe
        retq
        retq    $0xf

        .align  16

__itt_pt_byte:

        and     $0xff, %rdi
        call    __itt_pt_byte_pic
__itt_pt_byte_pic:
        popq    %rcx
        lea     (__itt_pt_byte_call_table - __itt_pt_byte_pic) (%rcx,%rdi,1), %rdi
        jmp     *%rdi

        .align  4

        .long   0xfadedeaf

__itt_pt_byte_call_table:

        .fill   256,1,0xc3

        .align  16

__itt_pt_event:
__itt_pt_event_int:

        pushq   %rcx
        xor     %rcx, %rcx
        rdpmc

        xor     %rdi, %rdi
        mov     %al, %dil
        call    __itt_pt_byte
        shr     $8, %eax
        mov     %al, %dil
        call    __itt_pt_byte
        shr     $8, %eax
        mov     %al, %dil
        call    __itt_pt_byte
        shr     $8, %eax
        mov     %al, %dil
        call    __itt_pt_byte

        mov     %dl, %dil
        call    __itt_pt_byte
        shr     $8, %edx
        mov     %dl, %dil
        call    __itt_pt_byte
        shr     $8, %edx
        mov     %dl, %dil
        call    __itt_pt_byte
        shr     $8, %edx
        mov     %dl, %dil
        call    __itt_pt_byte

        popq    %rcx
        ret

__itt_pt_mark_event:

        test    $1, %rdi
        jnz     odd
        mov     %rdi, %rsi
        call    __itt_pt_event_int
        mov     %rsi, %rdi
        jmp     __itt_pt_mark_int

odd:
        call    __itt_pt_mark_int
        jmp     __itt_pt_event_int


        .align  16

__itt_pt_flush:

        call    __itt_pt_flush_pic
__itt_pt_flush_pic:
        popq    %rdx
        lea     (__itt_pt_mark_flush_1 - __itt_pt_flush_pic) (%rdx), %rax
        jmp     *%rax

        .align   16
        nop
__itt_pt_mark_flush_1:
        lea     (__itt_pt_mark_flush_2 - __itt_pt_flush_pic) (%rdx), %rax
        jmp     *%rax

        .align   16
        nop
        nop
__itt_pt_mark_flush_2:
        lea     (__itt_pt_mark_flush_3 - __itt_pt_flush_pic) (%rdx), %rax
        jmp     *%rax

        .align   16
        nop
        nop
        nop
__itt_pt_mark_flush_3:
        ret

        .align  16

// int __itt_pt_mark_threshold(unsigned char index, unsigned long long* tmp, int threshold);

__itt_pt_mark_threshold:
        // rdi == index
        // rsi == tmp
        // rdx == threshold
        mov     %rdx, %r8 // r8 = threshold
        xor     %rdx, %rdx
        xor     %rax, %rax
        test    $1, %rdi
        jnz     mark_end
mark_begin:
        mov     $((1 << 30) + 1),%rcx
        rdpmc
        shl     $32, %rdx
        or      %rax, %rdx
        mov     %rdx, (%rsi)
        jmp     __itt_pt_mark_int
mark_end:
        mov     $((1 << 30) + 1),%rcx
        rdpmc
        shl     $32, %rdx
        or      %rax, %rdx
        sub     (%rsi), %rdx
        cmp     %r8, %rdx  // threshold
        jnc     found
        jmp     __itt_pt_mark_int
found:
        call    __itt_pt_mark_int
        jmp     __itt_pt_flush
