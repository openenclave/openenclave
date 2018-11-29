# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

from __future__ import print_function
import gdb
import struct
import os.path
from ctypes import create_string_buffer
import load_symbol_cmd

POINTER_SIZE = 8

# These constant definitions must align with _oe_enclave structure defined in host\enclave.h
OE_ENCLAVE_MAGIC_FIELD = 0
OE_ENCLAVE_ADDR_FIELD = 2
OE_ENCLAVE_HEADER_LENGTH = 0X28
OE_ENCLAVE_HEADER_FORMAT = 'QQQQQ'
OE_ENCLAVE_MAGIC_VALUE = 0x20dc98463a5ad8b8

# The following are the offset of the 'debug' and
# 'simulate' flag fields which must lie one after the other.
OE_ENCLAVE_FLAGS_OFFSET = 0x598
OE_ENCLAVE_FLAGS_LENGTH = 2
OE_ENCLAVE_FLAGS_FORMAT = 'BB'
OE_ENCLAVE_THREAD_BINDING_OFFSET = 0x28

# These constant definitions must align with ThreadBinding structure defined in host\enclave.h
THREAD_BINDING_SIZE = 0x28
THREAD_BINDING_HEADER_LENGTH = 0X8
THREAD_BINDING_HEADER_FORMAT = 'Q'

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

# Global enclave list parsed flag
g_enclave_list_parsed = False

def get_inferior():
    """Get current inferior"""
    try:
        if len(gdb.inferiors()) == 0:
            print ("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print ("This gdb's python support is too old, please update first.")
        exit()

def read_from_memory(addr, size):
    """Read data with specified size  from the specified memory"""
    inferior = get_inferior()
    # ( check the address is inside the enclave)
    if inferior == -1 or addr == 0:
        print ("Error happens in read_from_memory: addr = {0:x}".format(int(addr)))
        return None
    try:
        string = inferior.read_memory(addr, size)
        return string
    except gdb.MemoryError:
        print ("Can't access memory at {0:x}.".format(int(addr)))
        return None

def write_to_memory(addr, buf):
    """Write a specified buffer to the specified memory"""
    inferior = get_inferior()
    if inferior == -1 or addr == 0:
        print ("Error happens in write_to_memory: addr = {0:x}".format(int(addr)))
        return -1
    try:
        inferior.write_memory(addr, buf)
        return 0
    except gdb.MemoryError:
        print ("Can't access memory at {0:x}.".format(int(addr)))
        return -1

def target_path_to_host_path(target_path):
    so_name = os.path.basename(target_path)
    strpath = gdb.execute("show solib-search-path", False, True)
    path = strpath.split()[-1]
    strlen = len(path)
    if strlen != 1:
        path = path[0:strlen-1]
    host_path = path + "/" + so_name
    return host_path

def load_enclave_symbol(enclave_path, enclave_base_addr):
    """Load enclave symbol file into current debug session"""
    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)
    gdb_cmd = load_symbol_cmd.GetLoadSymbolCommand(enclave_path, str(enclave_base_addr))
    if gdb_cmd == -1:
        print ("Can't get symbol loading command.")
        return False
    # print (gdb_cmd)
    gdb.execute(gdb_cmd, False, True)
    # Store the oe_enclave address to global set that will be cleanup on exit.
    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.add(int(gdb_cmd.split()[2], 16))
    return True

def unload_enclave_symbol(enclave_path, enclave_base_addr):
    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)
    gdb_cmd = load_symbol_cmd.GetUnloadSymbolCommand(enclave_path, str(enclave_base_addr))
    if gdb_cmd == -1:
        print ("Can't get symbol unloading command.")
        return False
    # print (gdb_cmd)
    gdb.execute(gdb_cmd, False, True)
    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.discard(int(gdb_cmd.split()[2]))
    return True

def set_tcs_debug_flag(tcs_addr):
    string = read_from_memory(tcs_addr + 8, 4)
    if string == None:
        return False
    flag = struct.unpack('I', string)[0]
    flag |= 1
    gdb_cmd = "set *(unsigned int *)%#x = %#x" %(tcs_addr + 8, flag)
    # print ("set tcs [{0:#x}] flag, {1}" .format(tcs_addr, gdb_cmd))
    gdb.execute(gdb_cmd, False, True)
    return True

def enable_oeenclave_debug(oe_enclave_addr, enclave_path):
    """For a given OE enclave, load its symbol and enable debug flag for all its TCS"""
    # Check if the magic matches.
    enclave_blob = read_from_memory(oe_enclave_addr, OE_ENCLAVE_HEADER_LENGTH)
    enclave_tuple = struct.unpack(OE_ENCLAVE_HEADER_FORMAT, enclave_blob)
    if enclave_tuple[OE_ENCLAVE_MAGIC_FIELD] != OE_ENCLAVE_MAGIC_VALUE:
        return False
    # Check if it's SGX debug mode enclave.
    flags_blob = read_from_memory(oe_enclave_addr + OE_ENCLAVE_FLAGS_OFFSET, OE_ENCLAVE_FLAGS_LENGTH)
    flags_tuple = struct.unpack(OE_ENCLAVE_FLAGS_FORMAT, flags_blob)

    # Check if debugging is enabled.
    if flags_tuple[0] == 0:
        print ("oe-gdb: Debugging not enabled for enclave %s" % enclave_path)
        return False

    # Check if the enclave is loaded in simulation mode.
    if flags_tuple[1] != 0:
        print ("oe-gdb: Enclave %s loaded in simulation mode" % enclave_path)

    # Load symbol.
    if load_enclave_symbol(enclave_path, enclave_tuple[OE_ENCLAVE_ADDR_FIELD]) != 1:
        return False
    # Set debug flag for each TCS in this enclave.
    thread_binding_addr = oe_enclave_addr + OE_ENCLAVE_THREAD_BINDING_OFFSET
    thread_binding_blob = read_from_memory(thread_binding_addr, THREAD_BINDING_HEADER_LENGTH)
    thread_binding_tuple = struct.unpack(THREAD_BINDING_HEADER_FORMAT, thread_binding_blob)
    while thread_binding_tuple[0] > 0 :
        # print ("tcs address {0:#x}" .format(thread_binding_tuple[0]))
        set_tcs_debug_flag(thread_binding_tuple[0])
        # Iterate the array
        thread_binding_addr = thread_binding_addr + THREAD_BINDING_SIZE
        thread_binding_blob = read_from_memory(thread_binding_addr, THREAD_BINDING_HEADER_LENGTH)
        thread_binding_tuple = struct.unpack(THREAD_BINDING_HEADER_FORMAT, thread_binding_blob)
    return True

def update_untrusted_ocall_frame(frame_pointer, ocallcontext_tuple):
    """Update the untrusted ocall frame, so that untrusted stack can stitch withe the trusted stack"""
    if frame_pointer == 0 or ocallcontext_tuple == 0:
        return False
    # print ("Trusted ocall context at:{:#x}, rbp:{:#x}, return address:{:#x}" .format(ocallcontext_tuple[0], ocallcontext_tuple[OCALLCONTEXT_RBP], ocallcontext_tuple[OCALLCONTEXT_RET]))
    gdb_cmd = "set *(long *)%#x = %#x" %(frame_pointer, ocallcontext_tuple[OCALLCONTEXT_RBP])
    # print ("set ocall frame to trusted rbp, {}" .format(gdb_cmd))
    gdb.execute(gdb_cmd, False, True)
    gdb_cmd = "set *(long *)%#x = %#x" %(frame_pointer + POINTER_SIZE, ocallcontext_tuple[OCALLCONTEXT_RET])
    # print ("set ocall frame to trusted ret, {}" .format(gdb_cmd))
    gdb.execute(gdb_cmd, False, True)
    return True

class EnclaveCreationBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_notify_gdb_enclave_creation", internal=1)

    def stop(self):
        # Get oe_enclave_t.
        oe_enclave_addr = int(gdb.parse_and_eval("$rdi"))
        # Get enclave path string.
        enclave_path_addr = int(gdb.parse_and_eval("$rsi"));
        enclave_path_length = int(gdb.parse_and_eval("$rdx"));
        enclave_path_blob = read_from_memory(enclave_path_addr, enclave_path_length)
        dataFormat = str(enclave_path_length) + 's'
        enclave_path = struct.unpack_from(dataFormat, enclave_path_blob)[0].decode(encoding='UTF-8')
        # print ("Enclave path: {}" .format(enclave_path))
        # Enable enclave debug.
        enable_oeenclave_debug(oe_enclave_addr, enclave_path)
        return False

class EnclaveTerminationBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_notify_gdb_enclave_termination", internal=1)

    def stop(self):
        # Get oe_enclave_t.
        oe_enclave_addr = int(gdb.parse_and_eval("$rdi"))
        enclave_blob = read_from_memory(oe_enclave_addr, OE_ENCLAVE_HEADER_LENGTH)
        enclave_tuple = struct.unpack(OE_ENCLAVE_HEADER_FORMAT, enclave_blob)
        # Get enclave path string.
        enclave_path_addr = int(gdb.parse_and_eval("$rsi"));
        enclave_path_length = int(gdb.parse_and_eval("$rdx"));
        enclave_path_blob = read_from_memory(enclave_path_addr, enclave_path_length)
        dataFormat = str(enclave_path_length) + 's'
        enclave_path = struct.unpack_from(dataFormat, enclave_path_blob)[0].decode(encoding='UTF-8')
        # Unload the enclave symbol. Need not to reset the debug flag for TCSs.
        unload_enclave_symbol(enclave_path, enclave_tuple[OE_ENCLAVE_ADDR_FIELD])
        return False

class OCallStartBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_notify_ocall_start", internal=1)

    def stop(self):
        # Get untrusted stack frame pointer and corresponding TCS.
        frame_pointer = int(gdb.parse_and_eval("$rdi"))
        tcs_addr = int(gdb.parse_and_eval("$rsi"))
        # Get callsite of the TCS.
        td_addr = tcs_addr + TD_OFFSET_FROM_TCS
        callsite_pointer_addr = td_addr + TD_CALLSITE_OFFSET
        callsite_addr_blob = read_from_memory(callsite_pointer_addr, POINTER_SIZE)
        callsite_addr_tuple = struct.unpack_from('Q', callsite_addr_blob, 0)
        # print ("TD:{:#x}, callsite pointer:{:#x}, callsite address:{:#x}" .format(td_addr, callsite_pointer_addr, callsite_addr_tuple[0]))
        if callsite_addr_tuple[0] == 0:
            print ("ERROR: detect a invalid callsite0]")
            return False
        # Get ocallcontext of the callsite.
        ocallcontext_pointer_addr = callsite_addr_tuple[0] + CALLSITE_OCALLCONTEXT_OFFSET
        ocallconetxt_addr_blob = read_from_memory(ocallcontext_pointer_addr,POINTER_SIZE)
        ocallconetxt_addr_tuple = struct.unpack('Q', ocallconetxt_addr_blob)
        ocallcontext_blob = read_from_memory(ocallconetxt_addr_tuple[0], OCALLCONTEXT_LENGTH)
        ocallcontext_tuple = struct.unpack(OCALLCONTEXT_FORMAT, ocallcontext_blob)
        # Update ocall frame.
        update_untrusted_ocall_frame(frame_pointer, ocallcontext_tuple)
        return False

def new_objfile_handler(event):
    global g_enclave_list_parsed
    if not g_enclave_list_parsed:
        list_head = None        
        try:
            list_head = gdb.parse_and_eval("oe_enclave_list_head")            
        except:
            pass
        enclaves = []
        try:
            if list_head != None:
                print ("oe-gdb: Found global enclave list.")
                node_ptr = list_head['lh_first']
                while node_ptr != 0:
                    node = node_ptr.dereference()
                    enclave = node['enclave']
                    enclave_addr = int(enclave)
                    enclave_path = enclave.dereference()['path'].string('utf-8')
                    enclaves.append((enclave_addr, enclave_path))
                    node_ptr = node['next_entry']['le_next']
                

                # Set parsed to true. enable_oeenclave_debug loads the enclave
                # binary and therefore would trigger a recursive call to 
                # new_objfile_handler.Setting g_enclave_list_parsed breaks out 
                # the potential infinite recursion.
                g_enclave_list_parsed = True;

                print ("oe-gdb: %d enclaves in global enclave list." % len(enclaves))
                for (enclave_addr, enclave_path) in enclaves:
                    print("oe-gdb: Reading symbols from %s ..." % enclave_path, end='')    
                    enable_oeenclave_debug(enclave_addr, enclave_path)
                    print("done.")
        except:
            print("oe-gdb: Global enclave list processing failed.")
            g_enclave_list_parsed = True

def exited_handler(event):
    oe_debugger_cleanup()                

def oe_debugger_init():
    #execute "set displaced-stepping off" to workaround the gdb 7.11 issue
    gdb.execute("set displaced-stepping off", False, True)
    
    # When the inferior quits, execute cleanup.
    gdb.events.exited.connect(exited_handler)

    # Add a handler for every time an object file is loaded.
    # This is used when the debugger is attached to a running process.
    gdb.events.new_objfile.connect(new_objfile_handler)

    bps = gdb.breakpoints()
    if bps != None:
        for bp in bps:
            if bp.location == "oe_notify_gdb_enclave_creation" and bp.is_valid():
                return

    # Cleanup and set breakpoints.
    oe_debugger_cleanup()
    EnclaveCreationBreakpoint()
    EnclaveTerminationBreakpoint()
    OCallStartBreakpoint()
    return

def oe_debugger_cleanup():
    """Remove all loaded enclave symbols"""
    global g_enclave_list_parsed
    for oe_enclave_addr in g_loaded_oe_enclave_addrs:
        gdb_cmd = "remove-symbol-file -a %s" % (oe_enclave_addr)
        # print (gdb_cmd)
        gdb.execute("remove-symbol-file -a %s" % (oe_enclave_addr), False, True)
    g_loaded_oe_enclave_addrs.clear()
    g_enclave_list_parsed = False
    return

def exit_handler(event):
    oe_debugger_cleanup()
    return

if __name__ == "__main__":
    gdb.events.exited.connect(exit_handler)
    oe_debugger_init()
