# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import lldb
import sys

def lldb_eval(expr):
    return lldb.debugger.GetSelectedTarget().EvaluateExpression(expr)

def lldb_expr(expr):
    lldb.debugger.HandleCommand("expr " + expr)

def lldb_read_string(address):
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    return process.ReadCStringFromMemory(address, 32, lldb.SBError())

def lldb_quit():
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    process.Destroy()

def bp_main(frame, bp_loc, dict):
    print("** Hit breakpoint in main")
    argv_1 = lldb_eval("argv[1]")
    enclave = lldb_read_string(int(str(argv_1.value), 16))
    print("** enclave = " + enclave)
    return False

# Breakpoint in enc.c
def bp_enc_c_36(frame, bp_loc, dict):
    print("** Hit breakpoint in enclave")

    # Set debugger_test
    lldb_expr("debugger_test=1")
    debugger_test = lldb_eval("debugger_test")
    print("** debugger_test = %s" % debugger_test.value)

    if int(debugger_test.value) != 1:
        print("** Error: failed to set debugger_test")
        lldb_quit()

    return False

# Breakpoint in module_contructor
def bp_init_module(frame, bp_loc, dict):
    lldb_expr("is_module_init=1")
    return False

# Breakpoint by line number in module
def bp_module_c_13(frame, bp_loc, dict):
    # Check that value has been set
    is_module_init = lldb_eval("is_module_init")
    if int(is_module_init.value) != 1:
        print("** Error: is_module_init != 1")
        lldb_quit()
    print("** is_module_init = %s" % is_module_init.value)
    return False

# Breakpoint in module destructor
def bp_fini_module(frame, bp_loc, dict):
    # Calls don't work with hardware mode.
    # lldb_expr("notify_module_done_wrapper()")
    lldb_expr("module_fini=1")
    return False

# Breakpoint in square function
def bp_module_c_26(frame, bp_loc, dict):
    lldb_expr("r = a * a")
    return False

# Another breakpoint to test variable lookup
def bp_module_c_38(frame, bp_loc, dict):
    lldb_expr(" t = a + b + k")
    t = lldb_eval("t")
    print("t = %s" % t.value)
    return False

def run_test():
    lldb.debugger.SetAsync(False)
    target = lldb.debugger.GetSelectedTarget()

    bp = target.BreakpointCreateByName("main")
    bp.SetScriptCallbackFunction('commands.bp_main')

    bp = target.BreakpointCreateByLocation("enc.c", 36)
    bp.SetScriptCallbackFunction('commands.bp_enc_c_36')

    bp = target.BreakpointCreateByName("init_module")
    bp.SetScriptCallbackFunction('commands.bp_init_module')

    bp = target.BreakpointCreateByLocation("module.c", 13)
    bp.SetScriptCallbackFunction('commands.bp_module_c_13')

    bp = target.BreakpointCreateByName("fini_module")
    bp.SetScriptCallbackFunction('commands.bp_fini_module')

    bp = target.BreakpointCreateByLocation("module.c", 26)
    bp.SetScriptCallbackFunction('commands.bp_module_c_26')

    bp = target.BreakpointCreateByLocation("module.c", 38)
    bp.SetScriptCallbackFunction('commands.bp_module_c_38')

    # The `personality` syscall is used by lldb to turn off ASLR.
    # This syscall may not be permitted within containers.
    # Therefore, turn off disable-aslr.
    lldb.debugger.HandleCommand("settings set target.disable-aslr false")
    lldb.debugger.HandleCommand("run")

    # Run again to ensure that module is correctly unloaded/reloaded by debugger.
    lldb.debugger.HandleCommand("run")

    retval = lldb.debugger.GetSelectedTarget().GetProcess().exit_state
    if int(retval) == 0:
        print("oelldb-multi-module-test passed")
    else:
        print("oelldb-multi-module-test failed")

def __lldb_init_module(debugger, dict):
    run_test()
