# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

from __future__ import print_function
import gdb
import struct
import os.path
from ctypes import create_string_buffer
import load_symbol_cmd

POINTER_SIZE = 8

VERBOSE = False

# These constant definitions must align with oe_debug_enclave_t structure defined in debugrt/common.h
class oe_debug_module_t:
    OFFSETOF_MAGIC = 0
    SIZEOF_MAGIC = 8
    MAGIC_VALUE = 0xf67ae6230a18a2ce

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

    OFFSETOF_ENCLAVE = 56
    SIZEOF_ENCLAVE = 8

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
        self.enclave = read_int_from_memory(addr + self.OFFSETOF_ENCLAVE, self.SIZEOF_ENCLAVE)

    def is_valid(self):
        return self.magic == self.MAGIC_VALUE

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

    OFFSETOF_TCS_COUNT = 64
    SIZEOF_TCS_COUNT = 8

    OFFSETOF_FLAGS = 72
    SIZEOF_FLAGS = 8
    MASK_DEBUG = 0x01
    MASK_SIMULATE = 0x02

    OFFSETOF_MODULES = 80
    SIZEOF_MODULES = 8

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
        self.num_tcs = read_int_from_memory(addr + self.OFFSETOF_TCS_COUNT, self.SIZEOF_TCS_COUNT)
        tcs_ptr = read_int_from_memory(addr + self.OFFSETOF_TCS_ARRAY, self.SIZEOF_TCS_ARRAY)
        for i in range(0, self.num_tcs):
            tcs = read_int_from_memory(tcs_ptr, 8) # sizeof pointer is hard-coded to 8
            self.tcs.append(tcs)
            tcs_ptr += 8

        flags = read_int_from_memory(addr + self.OFFSETOF_FLAGS, self.SIZEOF_FLAGS)
        self.debug = bool(flags & self.MASK_DEBUG)
        self.simulate = bool(flags & self.MASK_SIMULATE)

        self.modules = read_int_from_memory(addr + self.OFFSETOF_MODULES, self.SIZEOF_MODULES)

    def is_valid(self):
        return self.magic == self.MAGIC_VALUE


# This constant definition must align with sgx_tcs_t
TCS_GSBASE_OFFSET =  56

# The set to store all loaded modules.
g_loaded_modules = []

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
    if VERBOSE:
        print (gdb_cmd)
    gdb.execute(gdb_cmd, False, True)
    # Store the oe_enclave address to global list that will be cleanup on exit.
    global g_loaded_modules
    g_loaded_modules.append((enclave_base_addr,
                             enclave_path,
                             int(gdb_cmd.split()[2], 16)))
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
    if VERBOSE:
        print (gdb_cmd)
    gdb.execute(gdb_cmd, False, True)
    global g_loaded_modules
    g_loaded_modules.remove((enclave_base_addr,
                             enclave_path,
                             int(gdb_cmd.split()[2])))
    return True

def set_tcs_debug_flag(tcs_addr):
    string = read_from_memory(tcs_addr + 8, 4)
    if string == None:
        return False
    flag = struct.unpack('I', string)[0]
    flag |= 1
    gdb_cmd = "set *(unsigned int *)%#x = %#x" %(tcs_addr + 8, flag)
    if VERBOSE:
        print ("set tcs [{0:#x}] flag, {1}" .format(tcs_addr, gdb_cmd))
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

class EnclaveCreationBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_debug_enclave_created_hook", internal=1)

    def stop(self):
        enclave_addr = int(gdb.parse_and_eval("$rdi"))
        enable_oeenclave_debug(enclave_addr)
        return False

class NonDebugEnclaveBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="_debug_non_debug_enclave_created_hook", internal=1)

    def stop(self):
        print ("oegdb: The enclave is not debuggable." +
               " Debugging non-debug enclaves using oegdb is unreliable and unstable." +
               " To make the enclave debuggable, set Debug=1 in the enclave's configuration and" +
               " add OE_ENCLAVE_FLAG_DEBUG to enclave creation flags.")
        return True

class EnclaveTerminationBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_debug_enclave_terminated_hook", internal=1)

    def stop(self):
        enclave_addr = int(gdb.parse_and_eval("$rdi"))
        enclave = oe_debug_enclave_t(enclave_addr)
        unload_enclave_symbol(enclave.path, enclave.base_address)
        return False

class ModuleLoadedBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_debug_module_loaded_hook", internal=1)

    def stop(self):
        module_addr = int(gdb.parse_and_eval("$rdi"))
        debug_module = oe_debug_module_t(module_addr)
        load_enclave_symbol(debug_module.path, debug_module.base_address)
        if VERBOSE:
            print ("oegdb: Loaded enclave module %s" % debug_module.path)
        return False

class ModuleUnloadedBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="oe_debug_module_unloaded_hook", internal=1)

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
            if bp.location == "oe_debug_enclave_created_hook" and bp.is_valid():
                return

    # Cleanup and set breakpoints.
    oe_debugger_cleanup()
    EnclaveCreationBreakpoint()
    EnclaveTerminationBreakpoint()
    ModuleLoadedBreakpoint()
    ModuleUnloadedBreakpoint()
    NonDebugEnclaveBreakpoint()
    return

def oe_debugger_cleanup():
    """Remove all loaded enclave symbols"""
    global g_enclave_list_parsed
    global g_loaded_modules
    for m in g_loaded_modules:
        gdb_cmd = "remove-symbol-file -a %s" % m[2]
        if VERBOSE:
            print (gdb_cmd)
        gdb.execute("remove-symbol-file -a %s" % m[2], False, True)
    g_loaded_modules.clear()
    g_enclave_list_parsed = False
    return

def exit_handler(event):
    oe_debugger_cleanup()
    return

if __name__ == "__main__":
    gdb.events.exited.connect(exit_handler)
    oe_debugger_init()
