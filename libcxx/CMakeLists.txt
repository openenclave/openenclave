# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# CMake project for CXX lib - re-archive the objects from
# external libcxx, libcxxrt, libunwind and wrap in easy-to-use CMake target
#
# Note: This approach might not work on Windows.
# Solutions are either to convert to OBJECT libraries (see below), or
# place/install all three libs (cxx, rt, unwind) and link against all
# three.

# Use intermediate project and add properties later using an interface library
include (ExternalProject)
ExternalProject_Add(oelibcxx_tmp
    DEPENDS cxxrt-static oelibcxx_unwind libcxx
    DOWNLOAD_COMMAND ""
        CONFIGURE_COMMAND ""
        BUILD_COMMAND sh -c "rm -f *.o ${OE_LIBDIR}/enclave/liboelibcxx.a"
            COMMAND ar x $<TARGET_FILE:cxxrt-static>
            COMMAND ar x ${PROJECT_BINARY_DIR}/3rdparty/libunwind/libunwind/src/.libs/libunwind.a
            COMMAND ar x $<TARGET_FILE:libcxx>
            COMMAND sh -c "ar qs ${OE_LIBDIR}/openenclave/enclave/liboelibcxx.a *.o"
        INSTALL_COMMAND ""
        )

# Interface lib to propagate includes&lib and install-rule
add_library(oelibcxx INTERFACE)
add_dependencies(oelibcxx oelibcxx_tmp)
target_link_libraries(oelibcxx INTERFACE
    $<BUILD_INTERFACE:${OE_LIBDIR}/openenclave/enclave/liboelibcxx.a>
    $<INSTALL_INTERFACE:\${_IMPORT_PREFIX}/${CMAKE_INSTALL_LIBDIR}/openenclave/enclave/liboelibcxx.a>
    )
target_link_libraries(oelibcxx INTERFACE libcxx)
install(FILES ${OE_LIBDIR}/openenclave/enclave/liboelibcxx.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install(TARGETS oelibcxx EXPORT openenclave-targets)

# At some point, we should convert the 3rdparty-libs into true CMake OBJECT libs,
# so we could source the objects directly like this:
#add_library(oelibcxx STATIC
#   $<TARGET_OBJECTS:cxxrt-static>
#   $<TARGET_OBJECTS:oelibcxx_unwind>
#   $<TARGET_OBJECTS:libcxx>
#   )
#target_link_libraries(oelibcxx cxxrt-static)
#target_link_libraries(oelibcxx oelibcxx_unwind)
#target_link_libraries(oelibcxx libcxx)
# assemble lib-archive into proper dir
#set_property(TARGET oelibcxx PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/enclave)
# install lib-archive upon install-time
#install (TARGETS oelibcxx EXPORT openenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/enclave)
