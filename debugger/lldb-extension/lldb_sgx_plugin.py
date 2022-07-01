# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

from __future__ import print_function
import lldb
import struct
import subprocess
import os.path
from ctypes import create_string_buffer

POINTER_SIZE = 8

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

# The set to store all loaded OE enclave base address.
g_loaded_oe_enclave_addrs = set()

# Global enclave list parsed flag
g_enclave_list_parsed = False

# The base enclave
g_enclave = None

# List of extra data regions
g_extra_data_regions = []

# Determine if the enclave uses OE based on the contract
g_using_oe = -1

def is_using_oe(frame):
    global g_using_oe
    if g_using_oe == -1:
        g_using_oe = False
        while frame:
            # Determine whether the enclave is using OE when callbacks are
            # invoked by walking up the stack and look for the following
            # function.
            if frame.name == "oe_sgx_build_enclave":
                g_using_oe = True
                break
            frame = frame.parent
    return g_using_oe

def read_from_memory(addr, size):
    process = lldb.debugger.GetSelectedTarget().GetProcess()
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

def read_int_from_memory(addr, size):
    mv = read_from_memory(addr, size)
    return int.from_bytes(mv, 'little')

def load_enclave_symbol(enclave_path, enclave_base_addr):
    """Load enclave symbol file into current debug session"""

    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        print("Cannot find enclave at " + enclave_path)
        return False

    lldb.debugger.HandleCommand("target modules add " + enclave_path)
    lldb.debugger.HandleCommand("target modules load --file " + enclave_path
                                + " -s " + str(enclave_base_addr))

    print("oelldb: Loaded symbols for %s" % enclave_path)

    # Store the oe_enclave address to global set that will be cleanup on exit.
    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.add(enclave_base_addr)
    return True

def unload_enclave_symbol(enclave_path, enclave_base_addr):
    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        print("Cannot find enclave at " + enclave_path)
        return

    target = lldb.debugger.GetSelectedTarget()
    module = target.FindModule(lldb.SBFileSpec(enclave_path))
    target.RemoveModule(module)

    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.discard(enclave_base_addr)

def set_tcs_debug_flag(tcs_addr):
    string = read_from_memory(tcs_addr + 8, 4)
    if string is None:
        return False
    flag = struct.unpack('I', string)[0]
    flag |= 1

    process = lldb.debugger.GetSelectedTarget().GetProcess()
    pid = process.GetProcessID();
    fd = os.open("/proc/" + str(pid) + "/mem", os.O_WRONLY)
    os.lseek(fd, int(tcs_addr + 8), 0);
    result = os.write(fd, struct.pack('I', flag));
    os.close(fd)
    if result != -1:
        return True
    else:
        print ("Can't access memory at {0:x}.".format(int(addr)) + "\n" + str(os.error))
        return None

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
        print ("oelldb: Debugging not enabled for enclave %s" % enclave.path)
        return False

    # Check if the enclave is loaded in simulation mode.
    if enclave.simulate != 0:
        print ("oelldb: Enclave %s loaded in simulation mode" % enclave.path)

    # Load symbols for the enclave
    if load_enclave_symbol(enclave.path, enclave.base_address) != 1:
        return False

    print("oelldb: Symbols loaded for enclave \n")
    for tcs in enclave.tcs:
        set_tcs_debug_flag(tcs)

    print("oelldb: All tcs set to debug for enclave \n")
    return True

class EnclaveCreationBreakpoint:
    def __init__(self, target):
        breakpoint  = target.BreakpointCreateByName("oe_debug_enclave_created_hook")
        breakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.EnclaveCreationBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        enclave_addr = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed
        enable_oeenclave_debug(enclave_addr)

        # Debugger is notified of the enclave *after* the enclave has been EINITed.
        # It is now OK to register any extra data region for which the registration has
        # been delayed.
        global g_extra_data_regions
        global g_enclave
        if g_extra_data_regions:
            for r in g_extra_data_regions:
                load_enclave_symbol(r.path, r.base_address)
            g_extra_data_regions = []

            # The code will reach here only if there were modules without enclave field
            # set. Therefore, this debugger can also be safely used for applications
            # that create multiple enclaves.
            g_enclave = enclave_addr
        return False

class NonDebugEnclaveBreakpoint:
    def __init__(self, target):
        breakpoint  = target.BreakpointCreateByName("_debug_non_debug_enclave_created_hook")
        breakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.NonDebugEnclaveBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        print ("oelldb: The enclave is not debuggable." +
               " Debugging non-debug enclaves using oelldb is unreliable and unstable." +
               " To make the enclave debuggable, set Debug=1 in the enclave's configuration and" +
               " add OE_ENCLAVE_FLAG_DEBUG to enclave creation flags.")
        return True

class EnclaveTerminationBreakpoint:
    def __init__(self, target):
        breakpoint  = target.BreakpointCreateByName("oe_debug_enclave_terminated_hook")
        breakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.EnclaveTerminationBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        enclave_addr = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed
        enclave = oe_debug_enclave_t(enclave_addr)
        unload_enclave_symbol(enclave.path, enclave.base_address)
        global g_enclave
        if g_enclave == enclave.base_address:
            g_enclave = None
        return False

class ModuleLoadedBreakpoint:
    def __init__(self, target):
        breakpoint = target.BreakpointCreateByName("oe_debug_module_loaded_hook")
        breakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.ModuleLoadedBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        library_image_addr = frame.FindValue("rdi", lldb.eValueTypeRegister).signed
        library_image = oe_debug_module_t(library_image_addr)
        if library_image.enclave != 0:
            load_enclave_symbol(library_image.path, library_image.base_address)
        elif g_enclave:
            # If g_enclave is not null, it means that the enclave was
            # EINITed and processed. It is OK to process region even though
            # the enclave field is null.
            load_enclave_symbol(library_image.path, library_image.base_address)
        elif not is_using_oe(frame):
            # If debugging a non-OE application, treating this breakpoint as normal
            # module loading.
            load_enclave_symbol(library_image.path, library_image.base_address)
        else:
            # For the use case of adding modules through the extra data feature,
            # the notifications for modules are sent before the enclave has been
            # EINITed. When the debugger tries to set any pending breakpoints in
            # these regions, the hardware fails the write operation. Therefore,
            # delay registering modules until after the enclave has been EINITed.
            global g_extra_data_regions
            g_extra_data_regions.append(library_image)
            print("oelldb: Delaying registration of region %s" % library_image.path)
        return False

class ModuleUnloadedBreakpoint:
    def __init__(self, target):
        breakpoint = target.BreakpointCreateByName("oe_debug_module_unloaded_hook")
        breakpoint.SetScriptCallbackFunction('lldb_sgx_plugin.ModuleUnloadedBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        library_image_addr = frame.FindValue("rdi", lldb.eValueTypeRegister).signed
        library_image = oe_debug_module_t(library_image_addr)
        unload_enclave_symbol(library_image.path, library_image.base_address)
        return False

def oe_debugger_init(debugger):
    EnclaveCreationBreakpoint(debugger.GetSelectedTarget())
    EnclaveTerminationBreakpoint(debugger.GetSelectedTarget())
    ModuleLoadedBreakpoint(debugger.GetSelectedTarget())
    ModuleUnloadedBreakpoint(debugger.GetSelectedTarget())
    NonDebugEnclaveBreakpoint(debugger.GetSelectedTarget())

# Invoked when `command script import lldb_sgx_plugin' is called.
def __lldb_init_module(debugger, dict):
    oe_debugger_init(debugger)
