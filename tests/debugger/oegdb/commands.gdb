# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Enable pending breakpoints
set breakpoint pending on

# Set a breakpoint in main (host)
b main
commands 1
    printf "** Hit breakpoint in main"
    printf "** enclave = %s\n", argv[1]
    continue
end

# Set a breakpoint in enc.c (enclave)
# This is a pending break point.
# Same line as function signature.
b enc.c:17
commands 2
    printf "** Hit breakpoint in enclave\n"

    # Test ability to introspect parameters
    printf "** a = %d, b = %d\n", a, b

    # Test values 
    if a != 5
        printf "** Error: a != 5\n"
        quit 1
    end

    # Test values 
    if b != 6
        printf "** Error: b != 6\n"
        quit 1
    end
    continue 
end

# Breakpoint in function body.
b enc.c:26
commands 3
    printf "** c = %d\n", c

    if c != 11
        printf "** Error: c != 11\n"
        quit 1
    end

    printf "Setting c\n"
    set variable c = 100
    continue
end

# Breakpoint in function body.
b enc.c:30
commands 4
    printf "** c = %d\n", c

    if c != 100
        printf "** Error: c != 100\n"
        quit 1
    end

    # Call a function defined within the enclave
    call square(c)

    set variable c = $1

    continue
end

# Assert debugger contract on host side.
b assert_debugger_binary_contract_host_side
commands 5
    python print("Serializing debugger contract on host side....")
    python import gdb_sgx_plugin

    python gdb.parse_and_eval("OFFSETOF_MAGIC = " + str(oe_debug_enclave_t.OFFSETOF_MAGIC))
    python gdb.parse_and_eval("SIZEOF_MAGIC = " + str(oe_debug_enclave_t.SIZEOF_MAGIC))
    python gdb.parse_and_eval("MAGIC_VALUE = " + str(oe_debug_enclave_t.MAGIC_VALUE))

    python gdb.parse_and_eval("OFFSETOF_VERSION = " + str(oe_debug_enclave_t.OFFSETOF_VERSION))
    python gdb.parse_and_eval("SIZEOF_VERSION = " + str(oe_debug_enclave_t.SIZEOF_VERSION))

    python gdb.parse_and_eval("OFFSETOF_NEXT = " + str(oe_debug_enclave_t.OFFSETOF_NEXT))
    python gdb.parse_and_eval("SIZEOF_NEXT = " + str(oe_debug_enclave_t.SIZEOF_NEXT))

    python gdb.parse_and_eval("OFFSETOF_PATH = " + str(oe_debug_enclave_t.OFFSETOF_PATH))
    python gdb.parse_and_eval("SIZEOF_PATH = " + str(oe_debug_enclave_t.SIZEOF_PATH))

    python gdb.parse_and_eval("OFFSETOF_PATH_LENGTH = " + str(oe_debug_enclave_t.OFFSETOF_PATH_LENGTH))
    python gdb.parse_and_eval("SIZEOF_PATH_LENGTH = " + str(oe_debug_enclave_t.SIZEOF_PATH_LENGTH))

    python gdb.parse_and_eval("OFFSETOF_BASE_ADDRESS = " + str(oe_debug_enclave_t.OFFSETOF_BASE_ADDRESS))
    python gdb.parse_and_eval("SIZEOF_BASE_ADDRESS = " + str(oe_debug_enclave_t.SIZEOF_BASE_ADDRESS))

    python gdb.parse_and_eval("OFFSETOF_SIZE = " + str(oe_debug_enclave_t.OFFSETOF_SIZE))
    python gdb.parse_and_eval("SIZEOF_SIZE = " + str(oe_debug_enclave_t.SIZEOF_SIZE))

    python gdb.parse_and_eval("OFFSETOF_TCS_ARRAY = " + str(oe_debug_enclave_t.OFFSETOF_TCS_ARRAY))
    python gdb.parse_and_eval("SIZEOF_TCS_ARRAY = " + str(oe_debug_enclave_t.SIZEOF_TCS_ARRAY))

    python gdb.parse_and_eval("OFFSETOF_NUM_TCS = " + str(oe_debug_enclave_t.OFFSETOF_NUM_TCS))
    python gdb.parse_and_eval("SIZEOF_NUM_TCS = " + str(oe_debug_enclave_t.SIZEOF_NUM_TCS))

    python gdb.parse_and_eval("OFFSETOF_FLAGS = " + str(oe_debug_enclave_t.OFFSETOF_FLAGS))
    python gdb.parse_and_eval("SIZEOF_FLAGS = " + str(oe_debug_enclave_t.SIZEOF_FLAGS))
    python gdb.parse_and_eval("MASK_DEBUG = " + str(oe_debug_enclave_t.MASK_DEBUG))
    python gdb.parse_and_eval("MASK_SIMULATE = " + str(oe_debug_enclave_t.MASK_SIMULATE))

    python print("Debugger contract serialized on host side.")
    continue
end

# Assert debugger contract on enclave side.
b assert_debugger_binary_contract_enclave_side
commands 6
    python print("Serializing debugger contract on enclave side....")
    python import gdb_sgx_plugin

    python gdb.parse_and_eval("TD_OFFSET_FROM_TCS = " + str(gdb_sgx_plugin.TD_OFFSET_FROM_TCS))
    python gdb.parse_and_eval("TD_CALLSITE_OFFSET = " + str(gdb_sgx_plugin.TD_CALLSITE_OFFSET))
    python gdb.parse_and_eval("CALLSITE_OCALLCONTEXT_OFFSET = " + str(gdb_sgx_plugin.CALLSITE_OCALLCONTEXT_OFFSET))

    python gdb.parse_and_eval("OCALLCONTEXT_LENGTH  = " + str(gdb_sgx_plugin.OCALLCONTEXT_LENGTH))
    python gdb.parse_and_eval("OCALLCONTEXT_FORMAT[0] = '" + gdb_sgx_plugin.OCALLCONTEXT_FORMAT[0] + "'")
    python gdb.parse_and_eval("OCALLCONTEXT_FORMAT[1] = '" + gdb_sgx_plugin.OCALLCONTEXT_FORMAT[1] + "'")
    python gdb.parse_and_eval("OCALLCONTEXT_RBP = " + str(gdb_sgx_plugin.OCALLCONTEXT_RBP))
    python gdb.parse_and_eval("OCALLCONTEXT_RET = " + str(gdb_sgx_plugin.OCALLCONTEXT_RET))

    python print("Debugger contract serialized on enclave side.")
    continue
end

# Run the program
run

# Check if program aborted or returned non zero.
if $_isvoid($_exitcode) || $_exitcode
    printf "** Test aborted\n"
    quit 1
end
