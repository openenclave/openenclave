# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# LVI Mitigation tests expect libraries to have the suffix .a.lvi-cfg.
# This is not the case for apkman libraries.
if (NOT LVI_MITIGATION STREQUAL "None")
  return()
endif ()

get_target_property(APKMAN_ROOT oeapkman ROOT)
message("APKMAN_ROOT = ${APKMAN_ROOT}")

add_subdirectory(zlib)
