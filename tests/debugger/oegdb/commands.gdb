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

# Run the program
run

# Check if program aborted or returned non zero.
if $_isvoid($_exitcode) || $_exitcode
    printf "** Test aborted\n"
    quit 1
end
