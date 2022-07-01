# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import lldb
import sys

def bp_enc_foo(frame, bp_loc, dict):
    print("This should not be hit")
    return True

def run_test():
    lldb.debugger.SetAsync(False)
    target = lldb.debugger.GetSelectedTarget()

    # Set breakpoint in enclave function. It should not be hit.
    bp = target.BreakpointCreateByName("enc_foo")
    bp.SetScriptCallbackFunction('commands.bp_enc_foo')

    # The `personality` syscall is used by lldb to turn off ASLR.
    # This syscall may not be permitted within containers.
    # Therefore, turn off disable-aslr.
    lldb.debugger.HandleCommand("settings set target.disable-aslr false")


    # Run the program. This will cause lldb to detect that a release-mode
    # enclave is being debugged and stop execution.
    lldb.debugger.HandleCommand("run")

    # Continue execution till end.
    lldb.debugger.HandleCommand("continue")

    retval = lldb.debugger.GetSelectedTarget().GetProcess().exit_state
    if int(retval) == 0:
        print("oelldb non debug enclave test passed")
    else:
        print("oelldb non debug enclave test failed")

def __lldb_init_module(debugger, dict):
    run_test()
