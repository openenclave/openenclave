# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (enclave_enable_fuzzing NAME)
  if (ENABLE_FUZZING)
    target_compile_definitions(${NAME} PRIVATE ENABLE_FUZZING)
    target_compile_options(
      ${NAME}
      PRIVATE
        -fsanitize=enclavefuzzer,enclaveaddress
        -fsanitize-address-instrument-interceptors
        -fsanitize-coverage=edge,indirect-calls,no-prune
        -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard
    )

    target_link_options(
      ${NAME}
      PRIVATE
      -fsanitize=enclavefuzzer,enclaveaddress
      -fsanitize-address-instrument-interceptors
      -fsanitize-coverage=edge,indirect-calls,no-prune
      -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)
  endif ()
endmacro (enclave_enable_fuzzing)

macro (host_enable_fuzzing NAME)
  if (ENABLE_FUZZING)
    target_compile_definitions(${NAME} PUBLIC ENABLE_FUZZING)
    target_compile_options(
      ${NAME}
      PRIVATE
        -fsanitize=fuzzer,address
        -fsanitize-coverage=edge,indirect-calls,no-prune
        -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard
    )

    target_link_options(
      ${NAME} PRIVATE -fsanitize=fuzzer,address
      -fsanitize-coverage=edge,indirect-calls,no-prune
      -fsanitize-coverage=trace-cmp,trace-div,trace-gep,trace-pc,trace-pc-guard)
  endif ()
endmacro (host_enable_fuzzing)
