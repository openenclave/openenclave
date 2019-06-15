# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeuteeasm
  ${OE_TZ_LIBUTEE_SRC}/arch/arm/utee_syscalls_a64.S
  ${OE_TZ_LIBUTEE_SRC}/arch/arm/gprof/gprof_a64.S)
set_property(TARGET oeuteeasm PROPERTY C_STANDARD 99)
target_compile_options(oeuteeasm PRIVATE
  ${OE_TZ_TA_S_FLAGS}
  -include ${OE_TZ_TA_DEV_KIT_CONF})
target_include_directories(oeuteeasm PRIVATE
  ${OE_TZ_LIBUTEE_INC}
  ${OE_TZ_LIBUTILS_EXT_INC})

# TODO: Include the files whose paths are commented out in the build.
add_library(oeutee
  ${OE_TZ_LIBUTEE_SRC}/tee_api_property.c
  ${OE_TZ_LIBUTEE_SRC}/abort.c
  #${OE_TZ_LIBUTEE_SRC}/trace_ext.c
  ${OE_TZ_LIBUTEE_SRC}/assert.c
  ${OE_TZ_LIBUTEE_SRC}/base64.c
  #${OE_TZ_LIBUTEE_SRC}/tee_api_arith.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api_objects.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api_operations.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api_se.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api_panic.c
  ${OE_TZ_LIBUTEE_SRC}/tee_tcpudp_socket.c
  ${OE_TZ_LIBUTEE_SRC}/tee_socket_pta.c
  ${OE_TZ_LIBUTEE_SRC}/arch/arm/user_ta_entry.c
  ${OE_TZ_LIBUTEE_SRC}/arch/arm/utee_misc.c
  ${OE_TZ_LIBUTILS_EXT_SRC}/buf_compare_ct.c)
set_property(TARGET oeutee PROPERTY C_STANDARD 99)
target_compile_options(oeutee PUBLIC
  -include ${OE_TZ_TA_DEV_KIT_CONF})
target_include_directories(oeutee PRIVATE
  ${OE_TZ_LIBUTEE_SRC}
  ${OE_TZ_LIBUTEE_INC}
  ${OE_TZ_LIBUTILS_EXT_INC}
  ${OE_TZ_LIBUTILS_ISOC_INC}
  ${OE_TZ_LIBMPA_INC})
target_link_libraries(oeutee PUBLIC
  oeuteeasm
  oelibc)

set_source_files_properties(
  ${OE_TZ_LIBUTEE_SRC}/tee_api_property.c
  ${OE_TZ_LIBUTEE_SRC}/base64.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api_objects.c
  ${OE_TZ_LIBUTEE_SRC}/tee_api_operations.c
  ${OE_TZ_LIBUTEE_SRC}/tee_tcpudp_socket.c
  ${OE_TZ_LIBUTEE_SRC}/tee_socket_pta.c
  ${OE_TZ_LIBUTEE_SRC}/arch/arm/user_ta_entry.c
  PROPERTIES
    COMPILE_FLAGS -Wno-conversion)

install(TARGETS oeutee oeuteeasm EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
