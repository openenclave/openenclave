# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# oeapkman is currently supported in Linux only.
if (NOT UNIX)
  return()
endif ()

if (OE_SGX)
  # oeapkman will work on Ubuntu 18.04 and Ubuntu 20.04 as is.
else ()
  # For OPTEE cross-compilation workflow, oeapkman needs QEMU user-mode
  # emulation.
  find_program(QEMU_AARCH64_STATIC qemu-aarch64-static)
  if (NOT QEMU_AARCH64_STATIC)
    message(
      WARNING "qemu-user-static package not installed. Skipping oeapkman tests."
    )
    return()
  endif ()
endif ()

# LVI Mitigation tests expect libraries to have the suffix .a.lvi-cfg.
# This is not the case for apkman libraries.
if (NOT LVI_MITIGATION STREQUAL "None")
  return()
endif ()

# Fetch the location of oeapkman binary.
get_target_property(OEAPKMAN oeapkman LOCATION)

# Execute oeapkman once so that it is initialized.
execute_process(COMMAND "${OEAPKMAN}")

# Execute oeapkman again to fetch the root folder.
execute_process(COMMAND "${OEAPKMAN}" root
                OUTPUT_VARIABLE APKMAN_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE)

message("APKMAN_ROOT is ${APKMAN_ROOT}")

add_subdirectory(sqlite)
add_subdirectory(zlib)
