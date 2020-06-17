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

    python gdb.parse_and_eval("TCS_GSBASE_OFFSET = " + str(gdb_sgx_plugin.TCS_GSBASE_OFFSET))

    python print("Debugger contract serialized on enclave side.")
    continue
end

# Assert that stack has been stitched correctly
b host.c:84
commands 7
    python print("\n\n\nWalking ocall stack....\n\n")
    # Read magic variable
    set $magic_value=magic_value

    # Set the magic variable in host_function.
    set host_function_magic=$magic_value

    # We expect at most 50 frames while walking the stack. Additionally a finite
    # iteration limit guarantees that the test will terminate quickly even if
    # the debugger is not able to walk the stack correctly.
    set $MAX_FRAMES=50

    # Walk the stack until the enclave function.
    # This asserts ocall stack stitching.
    set $i = $MAX_FRAMES
    while $i > 0
          up 1
          set $i=$i-1
          # Set the value of magic variable in enclave function.
          python if gdb.selected_frame().name() == "enclave_function": \
                        gdb.execute("set enc_magic=$magic_value"); \
                        gdb.execute("set $i=0")

    end

    # Continue walking the stack until main is reached.
    # This asserts ecall stack stitching.
    python print("\n\n\nWalking ecall stack...\n\n")
    set $i = $MAX_FRAMES
    while $i > 0
          up 1
          set $i=$i-1
          # Set the value of magic variable in enclave function.
          python if gdb.selected_frame().name() == "main": \
                        gdb.execute("set main_magic=$magic_value"); \
                        gdb.execute("set $i=0")

    end

    python print("\n\nStack stitching successfully validated\n\n")
    continue
end


# Run the program
run

# Check if program aborted or returned non zero.
if $_isvoid($_exitcode) || $_exitcode
    printf "** Test aborted\n"
    quit 1
end
