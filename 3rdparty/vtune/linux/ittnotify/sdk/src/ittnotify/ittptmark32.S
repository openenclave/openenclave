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

// /////////////////////////////////////////////////////////////////////////
////// Intel Processor Trace Marker Functionality
////////////////////////////////////////////////////////////////////////////

        .text
        .align  16
        .globl  __itt_pt_mark
        .globl  __itt_pt_event
        .globl  __itt_pt_mark_event
        .globl  __itt_pt_mark_threshold

/// void __itt_pt_mark(unsigned char index);
__itt_pt_mark:
        movzbl  4(%esp), %eax
        and     $0xf, %eax
        lea     __itt_pt_mark_call_table(,%eax,4), %eax
        jmp     *%eax
        .align  4
        .long   0xfadefade
__itt_pt_mark_call_table:
        ret
        ret    $0x0
        ret
        ret    $0x1
        ret
        ret    $0x2
        ret
        ret    $0x3
        ret
        ret    $0x4
        ret
        ret    $0x5
        ret
        ret    $0x6
        ret
        ret    $0x7
        ret
        ret    $0x8
        ret
        ret    $0x9
        ret
        ret    $0xa
        ret
        ret    $0xb
        ret
        ret    $0xc
        ret
        ret    $0xd
        ret
        ret    $0xe
        ret
        ret    $0xf

        .align  16

__itt_pt_byte:

        and     $0xff, %ecx
        lea     __itt_pt_byte_call_table(,%ecx,1), %ecx
        jmp     *%ecx

        .align  4

        .long   0xfadedeaf

__itt_pt_byte_call_table:

        .fill   256,1, 0xc3

        .align  16

__itt_pt_event:

        push   %ecx
        xor     %ecx, %ecx
        rdpmc

        mov     %al, %cl
        call    __itt_pt_byte
        shr     $8, %eax
        mov     %al, %cl
        call    __itt_pt_byte
        shr     $8, %eax
        mov     %al, %cl
        call    __itt_pt_byte
        shr     $8, %eax
        mov     %al, %cl
        call    __itt_pt_byte

        mov     %dl, %cl
        call    __itt_pt_byte
        shr     $8, %edx
        mov     %dl, %cl
        call    __itt_pt_byte
        shr     $8, %edx
        mov     %dl, %cl
        call    __itt_pt_byte
        shr     $8, %edx
        mov     %dl, %cl
        call    __itt_pt_byte

        pop    %ecx
        ret

__itt_pt_mark_event:

        testl   $1, 4(%esp)
        jnz     odd
        call    __itt_pt_event
        jmp     __itt_pt_mark

odd:
        call    __itt_pt_mark
        jmp     __itt_pt_event


        .align  16

__itt_pt_flush:

        lea     __itt_pt_mark_flush_1, %eax
        jmp     *%eax

        .align   16
        nop
__itt_pt_mark_flush_1:
        lea     __itt_pt_mark_flush_2, %eax
        jmp     *%eax

        .align   16
        nop
        nop
__itt_pt_mark_flush_2:
        lea     __itt_pt_mark_flush_3, %eax
        jmp     *%eax

        .align   16
        nop
        nop
        nop
__itt_pt_mark_flush_3:
        ret

        .align  16

// int __itt_pt_mark_threshold(unsigned char index, unsigned long long* tmp, int threshold);

__itt_pt_mark_threshold:
        //  4(%esp) == index
        //  8(%esp) == tmp
        // 12(%esp) == threshold
        xor     %edx, %edx
        xor     %eax, %eax

        testl   $1, 4(%esp)
        jnz     mark_end
mark_begin:
        mov     $((1 << 30) + 1),%ecx
        rdpmc
        mov     8(%esp), %ecx
        mov     %eax, (%ecx)
        mov     %edx, 4(%ecx)
        jmp     __itt_pt_mark
mark_end:
        mov     $((1 << 30) + 1),%ecx
        rdpmc
        mov     8(%esp), %ecx
        sub      (%ecx), %eax
        sbb     4(%ecx), %edx

        sub     12(%esp), %eax // threshold
        jnc     found
        sbb     $0, %edx
        jnc     found
        jmp     __itt_pt_mark
found:
        call    __itt_pt_mark
        jmp     __itt_pt_flush
