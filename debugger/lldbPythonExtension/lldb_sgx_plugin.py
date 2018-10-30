# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from __future__ import print_function
import struct
import os.path
import os
import lldb
from ctypes import create_string_buffer
import load_symbol_cmd
import ctypes, mmap, errno
from threading import Thread, Lock


POINTER_SIZE = 8

# These constant definitions must align with _oe_enclave structure defined in host\enclave.h
OE_ENCLAVE_MAGIC_FIELD = 0
OE_ENCLAVE_ADDR_FIELD = 2
OE_ENCLAVE_HEADER_LENGTH = 0X28
OE_ENCLAVE_HEADER_FORMAT = 'QQQQQ'
OE_ENCLAVE_MAGIC_VALUE = 0x20dc98463a5ad8b8

OE_ENCLAVE_FLAGS_OFFSET = 0x588
OE_ENCLAVE_FLAGS_LENGTH = 2
OE_ENCLAVE_FLAGS_FORMAT = 'BB'
OE_ENCLAVE_THREAD_DATA_OFFSET = 0x28

# These constant definitions must align with ThreadData structure defined in host\enclave.h
THREAD_DATA_SIZE = 0x28
THREAD_DATA_HEADER_LENGTH = 0X8
THREAD_DATA_HEADER_FORMAT = 'Q'

# This constant definition must align with the OE enclave layout.
TD_OFFSET_FROM_TCS =  0X4000
 
# This constant definition must align with TD structure in internal\sgxtypes.h.
TD_CALLSITE_OFFSET = 0XF0

# This constant definition must align with Callsite structure in enclave\td.h.
CALLSITE_OCALLCONTEXT_OFFSET = 0X40

# These constant definitions must align with OCallContext structure in enclave\td.h.
OCALLCONTEXT_LENGTH = 2 * 8
OCALLCONTEXT_FORMAT = 'QQ'
OCALLCONTEXT_RBP = 0
OCALLCONTEXT_RET = 1

# The set to store all loaded OE enclave base address.
g_loaded_oe_enclave_addrs = set()

def read_from_memory(process, addr, size):
    """Read data with specified size  from the specified memory"""
    # ( check the address is inside the enclave)
    if addr == 0:
        print ("Error happens in read_from_memory: addr = {0:x}".format(int(addr)))
        return None

    # process.ReadMemory() returns "memory read failed for" error while reading tcs_addr at least in lldb-7 and earlier 
    # that's why use system call to read memory
    pid = process.GetProcessID()

    fd = os.open("/proc/" + str(pid) + "/mem", os.O_RDONLY)
    os.lseek(fd, int(addr), 0)
    memory = os.read(fd, size)
    os.close(fd)

    if memory != -1:
        return memory
    else:
        print ("Can't access memory at {0:x}.".format(int(addr)) + "\n" + str(os.error))
        return None
        
def target_path_to_host_path(target_path):
    path_tuple = os.path.split(target_path)
    dir_name = path_tuple[0]
    if dir_name.startswith("./"):
        dir_name = dir_name[2:] 
    so_name = path_tuple[1]
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetCommandInterpreter().HandleCommand("target modules search-paths list", res)
    output = res.GetOutput().split('\n')
    rule = next(rule for rule in output if dir_name in rule)
    path = rule.split(" -> ")[1].strip('"')
    host_path = path + "/" + so_name
    if not host_path.startswith("/"):
        host_path = "./" + host_path
    return host_path


def load_enclave_symbol(enclave_path, enclave_base_addr):
    """Load enclave symbol file into current debug session"""

    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)
    lldb_cmd = load_symbol_cmd.GetLoadSymbolCommand(enclave_path, str(enclave_base_addr))
    if lldb_cmd == -1:
        print ("Can't get symbol loading command.")
        return False
    
    commands = lldb_cmd.split('\n')
    for cmd in commands:
        lldb.debugger.HandleCommand(cmd.encode('utf-8'))  

    # Store the oe_enclave address to global set that will be cleanup on exit.
    global g_loaded_oe_enclave_addrs
    arg_list = lldb_cmd.split();
    g_loaded_oe_enclave_addrs.add(int(arg_list[arg_list.index(".text") + 1], 16))
    return True

def unload_enclave_symbol(target, enclave_path, enclave_base_addr):
    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)
    
    module = target.FindModule(lldb.SBFileSpec(enclave_path.encode('utf-8')))
    target.RemoveModule(module)
    text_addr = load_symbol_cmd.GetTextAddr(enclave_path, str(enclave_base_addr))
    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.discard(text_addr)

    return True

def set_tcs_debug_flag(process, tcs_addr):
    string = read_from_memory(process, tcs_addr + 8, 4)
    if string is None:
        return False
    flag = struct.unpack('I', string)[0]
    flag |= 1

    pid = process.GetProcessID();
    fd = os.open("/proc/" + str(pid) + "/mem", os.O_WRONLY)
    os.lseek(fd, int(tcs_addr + 8), 0);
    
    #struct.pack is the only way to write C types into memory in Python
    result = os.write(fd, struct.pack('I', flag));

    #print(result)
    #print ("set tcs [{0:#x}] flag: {1}".format(tcs_addr, struct.pack('I', flag)))
    os.close(fd)
    if result != -1:
        return True
    else:
        print ("Can't access memory at {0:x}.".format(int(addr)) + "\n" + str(os.error))
        return None

def enable_oeenclave_debug(process, oe_enclave_addr, enclave_path):
    """For a given OE enclave, load its symbol and enable debug flag for all its TCS"""
    # Check if the magic matches.
    enclave_blob = read_from_memory(process, oe_enclave_addr, OE_ENCLAVE_HEADER_LENGTH)
    enclave_tuple = struct.unpack(OE_ENCLAVE_HEADER_FORMAT, enclave_blob)
    if enclave_tuple[OE_ENCLAVE_MAGIC_FIELD] != OE_ENCLAVE_MAGIC_VALUE:
        return False
    # Check if it's SGX debug mode enclave.
    flags_blob = read_from_memory(process, oe_enclave_addr + OE_ENCLAVE_FLAGS_OFFSET, OE_ENCLAVE_FLAGS_LENGTH)
    flags_tuple = struct.unpack(OE_ENCLAVE_FLAGS_FORMAT, flags_blob)
    # Debug == 1 and simulation == 0
    if flags_tuple[0] == 0 or flags_tuple[1] != 0:
        return False
    # Load symbol.
    if load_enclave_symbol(enclave_path, enclave_tuple[OE_ENCLAVE_ADDR_FIELD]) != 1:
        return False
    # Set debug flag for each TCS in this enclave.
    thread_data_addr = oe_enclave_addr + OE_ENCLAVE_THREAD_DATA_OFFSET
    thread_data_blob = read_from_memory(process, thread_data_addr, THREAD_DATA_HEADER_LENGTH)
    thread_data_tuple = struct.unpack(THREAD_DATA_HEADER_FORMAT, thread_data_blob)
    
    while thread_data_tuple[0] > 0 :
        # print ("tcs address {0:#x}" .format(thread_data_tuple[0]))
        set_tcs_debug_flag(process, thread_data_tuple[0])
        
        # Iterate the array
        thread_data_addr = thread_data_addr + THREAD_DATA_SIZE
        thread_data_blob = read_from_memory(process, thread_data_addr, THREAD_DATA_HEADER_LENGTH);
        thread_data_tuple = struct.unpack(THREAD_DATA_HEADER_FORMAT, thread_data_blob)
        
    return True

def update_untrusted_ocall_frame(process, frame_pointer, ocallcontext_tuple):
    """Update the untrusted ocall frame, so that untrusted stack can stitch withe the trusted stack"""
    if frame_pointer == 0 or ocallcontext_tuple == 0:
        return False

    pid = process.GetProcessID()
    fd = os.open("/proc/" + str(pid) + "/mem", os.O_WRONLY)
    
    os.lseek(fd, int(frame_pointer), 0)
    os.write(fd, struct.pack('l', ocallcontext_tuple[OCALLCONTEXT_RBP]))
    
    os.lseek(fd, int(frame_pointer + POINTER_SIZE), 0)
    os.write(fd, struct.pack('l', ocallcontext_tuple[OCALLCONTEXT_RET]))

    os.close(fd)
    return True


def onEnclaveCreation(frame, bp_loc, dict):

    # Get oe_enclave_t.
    oe_enclave_addr = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed

    # Get enclave path string.
    enclave_path_addr = frame.FindValue("rsi", lldb.eValueTypeRegister ).signed
    enclave_path_length = frame.FindValue("rdx", lldb.eValueTypeRegister ).signed

    thread = frame.GetThread()
    process = thread.GetProcess()
    enclave_path_blob = read_from_memory(process, enclave_path_addr, enclave_path_length)

    dataFormat = str(enclave_path_length) + 's'
    enclave_path = struct.unpack_from(dataFormat, enclave_path_blob)[0].decode(encoding='UTF-8')
    # print ("Enclave path: {}" .format(enclave_path))
    # Enable enclave debug.
    enable_oeenclave_debug(process, oe_enclave_addr, enclave_path)
    #thread = Thread(target = wait_for_exit, args = (process,))
    #thread.start()

    return False
    

def onEnclaveTermination(frame, bp_loc, dict):

    thread = frame.GetThread();
    process = thread.GetProcess();

    # Get oe_enclave_t.
    oe_enclave_addr = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed
    enclave_blob = read_from_memory(process, oe_enclave_addr, OE_ENCLAVE_HEADER_LENGTH)
    enclave_tuple = struct.unpack(OE_ENCLAVE_HEADER_FORMAT, enclave_blob)
    # Get enclave path string.
    enclave_path_addr = frame.FindValue("rsi", lldb.eValueTypeRegister ).signed
    enclave_path_length = frame.FindValue("rdx", lldb.eValueTypeRegister ).signed
    enclave_path_blob = read_from_memory(process, enclave_path_addr, enclave_path_length)
    dataFormat = str(enclave_path_length) + 's'
    enclave_path = struct.unpack_from(dataFormat, enclave_path_blob)[0].decode(encoding='UTF-8')
    # Unload the enclave symbol. Need not to reset the debug flag for TCSs.
    unload_enclave_symbol(process.GetTarget(), enclave_path, enclave_tuple[OE_ENCLAVE_ADDR_FIELD])
    return False


def onOCall(frame, bp_loc, dict):

    thread = frame.GetThread();
    process = thread.GetProcess();

    # Get untrusted stack frame pointer and corresponding TCS.
    frame_pointer = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed;
    tcs_addr = frame.FindValue("rsi", lldb.eValueTypeRegister ).signed;
    # Get callsite of the TCS.
    td_addr = tcs_addr + TD_OFFSET_FROM_TCS
    callsite_pointer_addr = td_addr + TD_CALLSITE_OFFSET
    callsite_addr_blob = read_from_memory(process, callsite_pointer_addr, POINTER_SIZE)
    callsite_addr_tuple = struct.unpack_from('Q', callsite_addr_blob, 0)
    # print ("TD:{:#x}, callsite pointer:{:#x}, callsite address:{:#x}" .format(td_addr, callsite_pointer_addr, callsite_addr_tuple[0]))
    if callsite_addr_tuple[0] == 0:
        print ("ERROR: detect a invalid callsite0]")
        return False
    # Get ocallcontext of the callsite.
    ocallcontext_pointer_addr = callsite_addr_tuple[0] + CALLSITE_OCALLCONTEXT_OFFSET
    ocallconetxt_addr_blob = read_from_memory(process, ocallcontext_pointer_addr,POINTER_SIZE)
    ocallconetxt_addr_tuple = struct.unpack('Q', ocallconetxt_addr_blob)
    ocallcontext_blob = read_from_memory(process, ocallconetxt_addr_tuple[0], OCALLCONTEXT_LENGTH)
    ocallcontext_tuple = struct.unpack(OCALLCONTEXT_FORMAT, ocallcontext_blob)
    # Update ocall frame.
    update_untrusted_ocall_frame(process, frame_pointer, ocallcontext_tuple)
    return False

def oe_debugger_init(debugger):
    target = debugger.GetSelectedTarget()

    # Cleanup and set breakpoints.
    oe_debugger_cleanup()
    enclaveCreationBreakpoint = target.BreakpointCreateByName("_oe_notify_gdb_enclave_creation")
    enclaveCreationBreakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.onEnclaveCreation')

    
    enclaveTerminationBreakpoint = target.BreakpointCreateByName("_oe_notify_gdb_enclave_termination")
    enclaveTerminationBreakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.onEnclaveTermination')
    
    oCallStartBreakpoint = target.BreakpointCreateByName("_oe_notify_ocall_start")
    oCallStartBreakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.onOCall')
    
    return


def oe_debugger_cleanup():
    """Remove all loaded enclave symbols"""
    target = lldb.target
    modules = target.modules
    for oe_enclave_addr in g_loaded_oe_enclave_addrs:
        for module in modules:
            if module.FindSection('.text').GetLoadAddress(targer) == oe_enclave_addr:
                target.RemoveModule(module)
    g_loaded_oe_enclave_addrs.clear()
    return

def exit_handler():
    oe_debugger_cleanup()
    return
   
''' 
def wait_for_exit(process):
    listener = lldb.SBListener("event_listener")
    process.GetBroadcaster().AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    done = False  
    while not done:
        event = lldb.SBEvent()
        if listener.WaitForEvent (1, event):
            state = process.GetStateFromEvent(event)
            if state == lldb.eStateExited:
            	exit_handler()
            	done = True
    return
'''

def __lldb_init_module(debugger, internal_dict):  
    oe_debugger_init(debugger)

