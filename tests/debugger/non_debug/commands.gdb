# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Enable pending breakpoints
set breakpoint pending on

# Set a breakpoint in enclave function
# This should not get hit.
b enc_foo
commands
    printf "This should not be hit\n"
end

# Run the program. This will cause GDB to detect that
# it is a non debug enclave and stop execution.
run

# Now that GDB is stopped, execute program till end.
c