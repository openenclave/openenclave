# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import gdb
import math
import tempfile

# Define variable `all` for use in `mprot addr all`
all = 1

class MystMprotectBreakpoint(gdb.Breakpoint):
    def __init__(self):
        # Register a breakpoint on the _mprotect function in the enclave.
        # myst_mprotect_ocall on the host side is invoked switchlessly, and thus
        # is not an appropriate spot to collect backtraces.
        super(MystMprotectBreakpoint, self).__init__('_mprotect', internal=False)
        self.calls = []
        self.bt_spec = []
        self.breaks = []
        self._welcome()
        self._disable()

    def stop(self):
        # Fetch the addr, len, prot parameters as well as the current thread.
        addr = int(gdb.parse_and_eval('(uint64_t)addr'))
        length = int(gdb.parse_and_eval('(uint64_t)len'))
        prot = int(gdb.parse_and_eval('(int)prot'))
        thread = int(gdb.parse_and_eval('$_thread'))
        bt = None
        index = len(self.calls) + 1
        # Check if backtrace needs to be captured or not.
        if self.bt_spec:
            frames = self.bt_spec[0]
            start_index = self.bt_spec[1]
            end_index = self.bt_spec[2]

            # If this call lies in the start and end index specification for
            # backtrace, capture the backtrace for specified number of frames.
            if index >= start_index and index <= end_index:
                bt = gdb.execute('bt %d' % frames, False, True)

        self.calls.append((addr, length, prot, bt, thread))
        # Check if a breakpoint has been requeste.
        if index in self.breaks:
            print("myst-prot: breaking at call %d" % index)
            # Stop execution
            return True

        # Continue execution.
        return False

    # Dispatch the command
    def dispatch(self, arg0, *args):
        if arg0 == "-b":
            self._add_breaks(*args)
        elif arg0 == "-bt":
            self._set_bt_spec(*args)
        elif arg0 == "-d":
            self._disable()
        elif arg0 == "-e":
            self._enable()
        elif arg0 == "-h":
            self._help()
        else:
            self._get_prot(arg0, *args)

    # Clear tracking information
    def clear(self):
        self.calls = []

    def _welcome(self):
        self._print('\nmyst-gdb has been configured to track mprotect calls.' +
                    '\nType myst-prot for more information\n')

    def _print(self, msg):
        print('\033[0;32m%s\033[0m' % msg)

    def _help(self):
        msg = 'myst-prot: Mystikos mprotect tracker\n' \
            'Commands:\n' \
            '  \033[0;32mmyst-prot <address-expression> [all]\033[0m\n' \
            '    Print matching mprotect calls for the given address.\n' \
            '    Examples:\n' \
            '      gdb) myst-prot $rip # Print the last mprotect call that contained the memory location $rip\n' \
            '      gdb) myst-prot 0xffabcdef all # Print all mprotect calls for given address\n' \
            '  \033[0;32mmyst-prot -bt <frames> [start-call-index [end-call-index]]\033[0m\n' \
            '    Start tracking given number of backtrace frames for mprotect calls.\n' \
            '    Examples:\n' \
            '      gdb) myst-prot -bt 15 # Track 15 frames for each mprotect call\n' \
            '      gdb) myst-prot -bt 30 1500 # Track 30 frames for 1500th mprotect call and beyond\n' \
            '  \033[0;32mmyst-prot -b call-index\033[0m\n' \
            '    Break at given call to mprotect\n' \
            '    Examples:\n' \
            '      gdb) myst-prot -b 1450 # Break at 1450th call to mprotect\n' \
            '  \033[0;32mmyst-prot -d\033[0m\n' \
            '    Disable mprotect tracking\n' \
            '  \033[0;32mmyst-prot -e\033[0m\n' \
            '    (Re)Enable mprotect tracking\n' \
            '  \033[0;32mmyst-prot [-h]\033[0m\n' \
            '    Print help\n'
        print(msg)

    def _set_bt_spec(self, frames=1000, start_index=1, end_index=pow(2,32)):
        self.bt_spec = (frames, start_index, end_index)

    def _add_breaks(self, *args):
        for a in args:
            self.breaks.append(int(a))

    def _disable(self):
        self.enabled = False
        print('mprotect tracking disabled.')

    def _enable(self):
        self.enabled = True
        print('mprotect tracking reenabled.')

    def _get_prot(self, addr_str, get_all=None):
        # Evaluate the address expression.
        addr = int(gdb.parse_and_eval(addr_str))
        print('address: %s = 0x%x' % (addr_str, addr))
        index = len(self.calls) + 1
        # Iterate though the calls in reverse order.
        for c in reversed(self.calls):
            index -= 1
            start = c[0]
            length = c[1]
            end = start + length
            end = math.ceil(end/4096) * 4096
            prot = c[2]
            bt = c[3]
            thread = c[4]
            if addr >= start and addr < end:
                print('matching mprotect call %d : thread %d, start=0x%x, adjusted end=0x%x, prot=%d, length = %d' %
                      (index, thread, start, end, prot, length))
                if bt:
                    print(bt)
                if not get_all:
                    break

mprotect_tracker = None

command = """
define myst-prot
  if $argc == 4
      python mprotect_tracker.dispatch("$arg0", $arg1, $arg2, $arg3)
  end
  if $argc == 3
      python mprotect_tracker.dispatch("$arg0", $arg1, $arg2)
  end
  if $argc == 2
      python mprotect_tracker.dispatch("$arg0", $arg1)
  end
  if $argc == 1
      python mprotect_tracker.dispatch("$arg0")
  end
  if $argc == 0
      python mprotect_tracker.dispatch("-h")
  end
end
"""

if __name__ == "__main__":
    mprotect_tracker = MystMprotectBreakpoint()

    # Register command with gdb.
    with tempfile.NamedTemporaryFile('w') as f:
        f.write(command)
        f.flush()
        gdb.execute('source %s' % f.name)
    def exit_handler(event):
       global mprotect_tracker
       mprotect_tracker.clear()
    gdb.events.exited.connect(exit_handler)
