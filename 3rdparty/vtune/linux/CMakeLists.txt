# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(ITTNOTIFY_COMPILE_OPTS
  -Wno-sign-conversion
  -Wno-sign-compare
  -fPIC)

add_library(ittnotify STATIC
    ittnotify/sdk/src/ittnotify/ittnotify_static.c
    ittnotify/sdk/src/ittnotify/jitprofiling.c)

maybe_build_using_clangw(ittnotify)

target_compile_options(ittnotify PRIVATE ${ITTNOTIFY_COMPILE_OPTS})

target_include_directories(ittnotify
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ittnotify/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ittnotify/sdk/src>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ittnotify/sdk/src/ittnotify)

# Link to dl lib
find_library(DL_LIB NAMES dl)

add_library(dl SHARED IMPORTED)

set_target_properties(dl PROPERTIES IMPORTED_LOCATION ${DL_LIB})

target_link_libraries(ittnotify dl)

# Install
install(TARGETS ittnotify
    EXPORT openenclave-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
