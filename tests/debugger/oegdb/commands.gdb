# Copyright (c) Microsoft Corporation. All rights reserved.
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

    python gdb.parse_and_eval("OE_ENCLAVE_MAGIC_FIELD = " + str(gdb_sgx_plugin.OE_ENCLAVE_MAGIC_FIELD))
    python gdb.parse_and_eval("OE_ENCLAVE_ADDR_FIELD = sizeof(void*) * " + str(gdb_sgx_plugin.OE_ENCLAVE_ADDR_FIELD))
    python gdb.parse_and_eval("OE_ENCLAVE_HEADER_LENGTH = " + str(gdb_sgx_plugin.OE_ENCLAVE_HEADER_LENGTH))
    python gdb.parse_and_eval('sprintf(OE_ENCLAVE_HEADER_FORMAT, "%s", "' + gdb_sgx_plugin.OE_ENCLAVE_HEADER_FORMAT + '")')
    python gdb.parse_and_eval("OE_ENCLAVE_MAGIC_VALUE = " + str(gdb_sgx_plugin.OE_ENCLAVE_MAGIC_VALUE))

    python gdb.parse_and_eval("OE_ENCLAVE_FLAGS_OFFSET = " + str(gdb_sgx_plugin.OE_ENCLAVE_FLAGS_OFFSET))
    python gdb.parse_and_eval("OE_ENCLAVE_FLAGS_LENGTH = " + str(gdb_sgx_plugin.OE_ENCLAVE_FLAGS_LENGTH))
    python gdb.parse_and_eval('sprintf(OE_ENCLAVE_FLAGS_FORMAT, "%s", "' + gdb_sgx_plugin.OE_ENCLAVE_FLAGS_FORMAT + '")')
    python gdb.parse_and_eval("OE_ENCLAVE_THREAD_BINDING_OFFSET = " + str(gdb_sgx_plugin.OE_ENCLAVE_THREAD_BINDING_OFFSET))

    python gdb.parse_and_eval("THREAD_BINDING_SIZE = " + str(gdb_sgx_plugin.THREAD_BINDING_SIZE))
    python gdb.parse_and_eval("THREAD_BINDING_HEADER_LENGTH = " + str(gdb_sgx_plugin.THREAD_BINDING_HEADER_LENGTH))
    python gdb.parse_and_eval('sprintf(THREAD_BINDING_HEADER_FORMAT, "%s", "' + gdb_sgx_plugin.THREAD_BINDING_HEADER_FORMAT + '")')

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
