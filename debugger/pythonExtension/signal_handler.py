# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import gdb
import sys

# Instructions for which SIGILL is ignored.
ignored_instructions = set()

# Get mnemonic at pc.
def get_sigill_mnemonic():
    try:
        frame = gdb.newest_frame()
        # Disassemble to find out the instruction
        # See: https://wiki.osdev.org/X86-64_Instruction_Encoding
        max_instruction_length = 15
        start_pc = frame.pc()
        end_pc = start_pc + max_instruction_length
        asm = frame.architecture().disassemble(start_pc= start_pc,
                                               end_pc = end_pc)

        insn = asm[0]['asm']
        mnemonic = insn.split()[0]
        return mnemonic
    except:
        return None

def oe_stop_event_handler(event):
    if isinstance(event, gdb.SignalEvent) and event.stop_signal == "SIGILL":
        insn = get_sigill_mnemonic()
        if insn in ignored_instructions:
            print("oegdb: Ignoring sigill from " + insn +  ".")
            gdb.execute("continue", from_tty=True, to_string=False)

class IgnoreSigill(gdb.Command):
    """ Ignore SIGILL raised by given instruction """
    def __init__(self):
        super(IgnoreSigill, self).__init__('oegdb-ignore-sigill', gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        ignored_instructions.add(arg)
        if from_tty:
            print("oegdb: Added " + arg + " to SIGILL ignore list.")


def register():
    IgnoreSigill()
    gdb.events.stop.connect(oe_stop_event_handler)
    print("oegdb: Registered stop event handler to handle SIGILL.\n")
    gdb.execute("oegdb-ignore-sigill cpuid", from_tty=True)

def unregister():
    try:
        gdb.events.stop.disconnect(oe_stop_event_handler)
    except:
        pass
