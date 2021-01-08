# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

from __future__ import print_function
import gdb
import struct
import os.path
from ctypes import create_string_buffer
import load_symbol_cmd

POINTER_SIZE = 8

# These constant definitions must align with oe_debug_enclave_t structure defined in debugrt/host.h
class oe_debug_enclave_t:
    OFFSETOF_MAGIC = 0
    SIZEOF_MAGIC = 8
    MAGIC_VALUE = 0xabc540ee14fa48ce

    OFFSETOF_VERSION = 8
    SIZEOF_VERSION = 8

    OFFSETOF_NEXT = 16
    SIZEOF_NEXT = 8

    OFFSETOF_PATH = 24
    SIZEOF_PATH = 8

    OFFSETOF_PATH_LENGTH = 32
    SIZEOF_PATH_LENGTH = 8

    OFFSETOF_BASE_ADDRESS = 40
    SIZEOF_BASE_ADDRESS = 8

    OFFSETOF_SIZE = 48
    SIZEOF_SIZE = 8

    OFFSETOF_TCS_ARRAY = 56
    SIZEOF_TCS_ARRAY = 8

    OFFSETOF_NUM_TCS = 64
    SIZEOF_NUM_TCS = 8

    OFFSETOF_FLAGS = 72
    SIZEOF_FLAGS = 8
    MASK_DEBUG = 0x01
    MASK_SIMULATE = 0x02

    def __init__(self, addr):
        if addr:
            self.magic = read_int_from_memory(addr + self.OFFSETOF_MAGIC, self.SIZEOF_MAGIC)
        if not self.is_valid():
            return

        self.version = read_int_from_memory(addr + self.OFFSETOF_VERSION, self.SIZEOF_VERSION)
        self.next = read_int_from_memory(addr + self.OFFSETOF_NEXT, self.SIZEOF_NEXT)

        path = read_int_from_memory(addr + self.OFFSETOF_PATH, self.SIZEOF_PATH)
        path_length = read_int_from_memory(addr + self.OFFSETOF_PATH_LENGTH, self.SIZEOF_PATH_LENGTH)
        self.path = bytes(read_from_memory(path, path_length)).decode('utf-8')

        self.base_address = read_int_from_memory(addr + self.OFFSETOF_BASE_ADDRESS, self.SIZEOF_BASE_ADDRESS)

        self.tcs = []
        self.num_tcs = read_int_from_memory(addr + self.OFFSETOF_NUM_TCS, self.SIZEOF_NUM_TCS)
        tcs_ptr = read_int_from_memory(addr + self.OFFSETOF_TCS_ARRAY, self.SIZEOF_TCS_ARRAY)
        for i in range(0, self.num_tcs):
            tcs = read_int_from_memory(tcs_ptr, 8) # sizeof pointer is hard-coded to 8
            self.tcs.append(tcs)
            tcs_ptr += 8

        flags = read_int_from_memory(addr + self.OFFSETOF_FLAGS, self.SIZEOF_FLAGS)
        self.debug = bool(flags & self.MASK_DEBUG)
        self.simulate = bool(flags & self.MASK_SIMULATE)


    def is_valid(self):
        return self.magic == self.MAGIC_VALUE

class oe_debug_module_t:
    OFFSETOF_MAGIC = 0
    SIZEOF_MAGIC = 8
    MAGIC_VALUE  = 0x0ccad3302d644b28

    OFFSETOF_VERSION = 8
    SIZEOF_VERSION = 8

    OFFSETOF_PATH = 16
    SIZEOF_PATH = 8

    OFFSETOF_PATH_LENGTH = 24
    SIZEOF_PATH_LENGTH = 8

    OFFSETOF_BASE_ADDRESS = 32
    SIZEOF_BASE_ADDRESS = 8

    OFFSETOF_SIZE = 40
    SIZEOF_SIZE = 8

    def __init__(self, addr):
        if addr:
            self.magic = read_int_from_memory(addr + self.OFFSETOF_MAGIC, self.SIZEOF_MAGIC)
        if not self.is_valid():
            return

        self.version = read_int_from_memory(addr + self.OFFSETOF_VERSION, self.SIZEOF_VERSION)
        path = read_int_from_memory(addr + self.OFFSETOF_PATH, self.SIZEOF_PATH)
        path_length = read_int_from_memory(addr + self.OFFSETOF_PATH_LENGTH, self.SIZEOF_PATH_LENGTH)
        self.path = bytes(read_from_memory(path, path_length)).decode('utf-8')
        self.base_address = read_int_from_memory(addr + self.OFFSETOF_BASE_ADDRESS, self.SIZEOF_BASE_ADDRESS)

    def is_valid(self):
        return self.magic == self.MAGIC_VALUE


# This constant definition must align with sgx_tcs_t
TCS_GSBASE_OFFSET =  56

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

def read_int_from_memory(addr, size):
    mv = read_from_memory(addr, size)
    return int.from_bytes(mv, 'little')

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

def enable_oeenclave_debug(oe_enclave_addr):
    """For a given OE enclave, load its symbol and enable debug flag for all its TCS"""

    enclave = oe_debug_enclave_t(oe_enclave_addr)

    # Check if magic matches
    if not enclave.is_valid():
        return False

    # No version specific checks.
    # The contract will be extended in backwards compatible manner.
    # Debugger may use version to take specific actions in future.

    # Check if debugging is enabled.
    if enclave.debug == 0:
        print ("oegdb: Debugging not enabled for enclave %s" % enclave.path)
        return False

    # Check if the enclave is loaded in simulation mode.
    if enclave.simulate != 0:
        print ("oegdb: Enclave %s loaded in simulation mode" % enclave.path)

    # Load symbols for the enclave
    if load_enclave_symbol(enclave.path, enclave.base_address) != 1:
        return False

    print("oegdb: Symbols loaded for enclave \n")
    for tcs in enclave.tcs:
        set_tcs_debug_flag(tcs)

    print("oegdb: All tcs set to debug for enclave \n")
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
        gdb.Breakpoint.__init__ (self, spec="oe_notify_debugger_enclave_creation", internal=1)

    def stop(self):
        enclave_addr = int(gdb.parse_and_eval("$rdi"))
        enable_oeenclave_debug(enclave_addr)
        return False

class EnclaveTerminationBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_notify_debugger_enclave_termination", internal=1)

    def stop(self):
        enclave_addr = int(gdb.parse_and_eval("$rdi"))
        enclave = oe_debug_enclave_t(enclave_addr)
        unload_enclave_symbol(enclave.path, enclave.base_address)
        return False

class ModuleLoadBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_notify_debugger_module_load", internal=1)

    def stop(self):
        module_addr = int(gdb.parse_and_eval("$rdi"))
        debug_module = oe_debug_module_t(module_addr)
        load_enclave_symbol(debug_module.path, debug_module.base_address)
        print ("oegdb: Loaded enclave module %s" % debug_module.path)
        return False

class ModuleUnloadBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_notify_debugger_module_unload", internal=1)

    def stop(self):
        module_addr = int(gdb.parse_and_eval("$rdi"))
        debug_module = oe_debug_module_t(module_addr)
        unload_enclave_symbol(debug_module.path, debug_module.base_address)
        print ("oegdb: Unloaded enclave module %s" % debug_module.path)
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
                print ("oegdb: Found global enclave list.")
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

                print ("oegdb: %d enclaves in global enclave list." % len(enclaves))
                for (enclave_addr, enclave_path) in enclaves:
                    print("oegdb: Reading symbols from %s ..." % enclave_path, end='')
                    enable_oeenclave_debug(enclave_addr, enclave_path)
                    print("done.")
        except:
            print("oegdb: Global enclave list processing failed.")
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
            if bp.location == "oe_notify_debugger_enclave_creation" and bp.is_valid():
                return

    # Cleanup and set breakpoints.
    oe_debugger_cleanup()
    EnclaveCreationBreakpoint()
    EnclaveTerminationBreakpoint()
    ModuleLoadBreakpoint()
    ModuleUnloadBreakpoint()
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
