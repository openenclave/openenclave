# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_test(NAME tests/tools/apkman/ocaml
         COMMAND bash -c "echo 1*2*3*4*5 | host/ocaml_host enc/ocaml_enc")
