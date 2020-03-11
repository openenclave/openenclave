#
# Copyright (C) 2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

import sys
import os
import re
import shutil
import random

LOCK = "lock"
REP = "rep[a-z]*"
REX = "rex(?:\.[a-zA-Z]+)?"
SCALAR = "(?:(?:[+-]\s*)?(?:[0-9][0-9a-fA-F]*|0x[0-9a-fA-F]+))"
IMMEDIATE = "(?:%s[hb]?)" %(SCALAR)
REG = "(?:%[a-zA-Z][a-zA-Z0-9]*)"
SYM = "(?:[_a-zA-Z][_a-zA-Z0-9]*(?:@[0-9a-zA-Z]+)?)"
LABEL = "(?:[._a-zA-Z0-9]+)"
SEP = "(?:(?:^|:)\s*)"
PFX = "(?:%s\s+)?" %(REX)
CONST = "(?:(?:%s|%s|%s)(?:\s*[/*+-]\s*(?:%s|%s|%s))*)" %(SYM, SCALAR, LABEL, SYM, SCALAR, LABEL)
OFFSET = "(?:%s|%s|%s\s*:\s*(?:%s|%s|))" %(CONST, SYM, REG, CONST, SYM)
MEMORYOP = "(?:(?:\(*%s*\)*)*\(%s\s*(?:,\s*%s*\s*,\s*%s*\s*)*\))" %(CONST, REG, REG, CONST)
MEMORYOP = "(?:(?:\(*%s\)*)*\(%s\s*(?:,\s*%s*\s*,\s*%s*\s*)*\))" %(CONST, REG, REG, CONST)
ANYOP = "(?:%s|%s|%s|%s|%s)" %(MEMORYOP, IMMEDIATE, REG, SYM, LABEL)
MEMORYSRC = "(?:%s,\s*)" %(MEMORYOP)
MEMORYANY = "(?:%s,\s*)%s*(?:\s*,\s*%s)*" % (MEMORYOP, ANYOP, ANYOP)
ATTSTAR = "\*"

LFENCE = [
    "(?:%s%smov(?:[a-rt-z][a-z0-9]*)?\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%s(?:vpmask|mask|c|v|p|vp)mov[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%spop[bswlqt]?\s+(?:%s|%s))" %(SEP, PFX, MEMORYOP, REG),
    "(?:%s%spopad?\s+%s\s*)" %(SEP, PFX, REG),
    "(?:%s%s(?:%s\s+)?xchg[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?(?:x|p|vp|ph|h|pm|)add[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?(?:p|vp|ph|h|)sub[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?ad[co]x?[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?sbb[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?(?:p|)cmp(?:[a-rt-z][a-z0-9]*)?\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?inc[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?dec[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?not[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?neg[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:i|v|p|vp|)mul[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s(?:i|v|p|vp|)div[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%spopcnt[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%scrc32[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s(?:%s\s+)?v?p?and[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?v?p?or[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?v?p?xor[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%sv?p?test[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%ss[ah][lr][a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%ssar[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sro(?:r|l)[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%src(?:r|l)[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s(?:%s\s+)?bt[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%sbs[fr][a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s[lt]zcnt[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sblsi[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sblsmsk[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sblsr[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sbextr[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sbzhi[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%spdep[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%spext[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?lods[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?scas[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?outs[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?cmps[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?movs[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%slddqu\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?pack[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?punpck[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?pshuf[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?palign[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?pblend[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%svperm[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?p?insr[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%svinsert[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?p?expand[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%svp?broadcast[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%svp?gather[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?pavg[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?p?min[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?p?max[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?phminpos[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?pabs[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psign[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?m?psad[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psll[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psrl[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psra[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?pclmulqdq\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aesdec(?:last)?\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aesenc(?:last)?\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aesimc\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aeskeygenassist\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?sha(?:1|256)(?:nexte|rnds4|msg1|msg2)\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?cvt[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?rcp(?:ss|ps)\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?u?comis[sd]\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?round[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?dpp[sd]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?r?sqrt[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?ldmxcsr\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%sf?x?rstors?\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%sl[gi]dt\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%slmsw\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%svmptrld\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%sf(?:b|i|)ld[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?add[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?sub[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?mul[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?div[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sf(?:i|u|)com[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
]

RET = "(?:%s%sret[a-z]*(?:\s+%s)?(?:#|$))" %(SEP, PFX, IMMEDIATE)
MEM_INDBR = "(?:%s%s(call|jmp)[a-z]*\s+%s%s)" %(SEP, PFX, ATTSTAR, MEMORYOP)
REG_INDBR = "(?:%s%s(call|jmp)[a-z]*\s+%s%s)" %(SEP, PFX, ATTSTAR, REG)

#
# File Operations - read/write
#
def read_file(sfile):
    f = open(sfile, 'r')
    lines = f.readlines()
    f.close()
    return lines

def write_file(tfile, lines):
    f = open(tfile, 'w')
    for line in lines:
        f.write(line)
    f.close()
    return

def insert_lfence(mitigation_level, infile, outfile):
    pattern = '|'.join('(?:%s)' % l for l in LFENCE)
    lines = read_file(infile)
    outputs = lines
    for i in range(0, len(lines)):
        if lines[i].strip().startswith('#') or lines[i].strip().startswith('.'):
            continue
        if mitigation_level == 1:
            # harden loads
            m = re.search(pattern, lines[i])
            if m:
                j = i
                while j > 0:
                    j = j + 1
                    if outputs[j].strip() != '':
                        break
                if not outputs[j].strip().startswith('lfence'):
                    load_mitigation = "    lfence\n"
                    outputs[i] = outputs[i] + load_mitigation
                    continue
            # harden ret
            m = re.search(RET, lines[i])
            if m:
                ret_mitigation = "    notq (%rsp)\n    notq (%rsp)\n    lfence\n"
                outputs[i] = ret_mitigation + outputs[i]
        elif mitigation_level == 2:
            # harden ret
            m = re.search(RET, lines[i])
            if m:
                ret_mitigation = "    notq (%rsp)\n    notq (%rsp)\n    lfence\n"
                outputs[i] = ret_mitigation + outputs[i]
                continue
            # harden indirect branches
            m = re.search(REG_INDBR, lines[i])
            if m:
                j = i
                while j > 0:
                    j = j - 1
                    if outputs[j].strip() != '':
                        break
                if not outputs[j].split('\n')[-2].strip().startswith('lfence'):
                    outputs[i] = "    lfence\n" + outputs[i]
            m = re.search(MEM_INDBR, lines[i])
            if m:
                print ("Warning: indirect branch with memory operand, line %d" % i)

    write_file(outfile, outputs)

def parse_options():
    mitigation = 0
    options = []
    for arg in sys.argv[1:]:
        if arg == '-DMITIGATION=FULL':
            mitigation = 1
        elif arg == '-DMITIGATION=CONTROLFLOW':
            mitigation = 2
        else:
            options.append(arg)
    return (mitigation, options)

def get_src_index(options):
    src_index = -1
    for i in range(0,len(options)):
        if options[i] == '-s':
            if(src_index != -1):
                print ('source files conflict')
                exit(-1)
            src_index = i+1
    if src_index == -1:
        print ('cannot find the source file')
        exit(-1)
    return src_index

def get_dst_index(options):
    dst_index = -1
    for i in range(0,len(options)):
        if options[i] == '-o':
            if(dst_index != -1):
                print ('target files conflict')
                exit(-1)
            dst_index = i+1
    if dst_index == -1:
        print ('cannot find the target file')
        exit(-1)
    return dst_index

if __name__ == "__main__":
    (mitigation, options) = parse_options()

    src_index = get_src_index(options)
    src_file = options[src_index]
    dst_index = get_dst_index(options)
    dst_file = options[dst_index]

    # insert lfence
    insert_lfence(mitigation, src_file, dst_file)
