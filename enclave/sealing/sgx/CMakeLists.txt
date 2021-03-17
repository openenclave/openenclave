# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (add_seal_plugin_sgx NAME)
  add_seal_plugin(${NAME} ${ARGN})
  enclave_compile_options(
    ${NAME}
    PRIVATE
    -fPIE
    -nostdinc
    -fstack-protector-strong
    -fvisibility=hidden
    -fno-omit-frame-pointer
    -ffunction-sections
    -fdata-sections
    -ftls-model=local-exec)
  enclave_include_directories(${NAME} PRIVATE ../../core/sgx)
endmacro ()

add_seal_plugin_sgx(oeseal_gcmaes seal_gcmaes.c)

maybe_build_using_clangw(oeseal_gcmaes)
