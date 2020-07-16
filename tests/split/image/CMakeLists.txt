# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(image image.c)

target_link_libraries(
  image
  -nostdlib
  -nodefaultlibs
  -nostartfiles
  -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id
  -Wl,-z,noexecstack
  -Wl,-z,now
  -Wl,-gc-sections)
