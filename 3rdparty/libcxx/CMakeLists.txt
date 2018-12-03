# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy headers to collector-dir, patch, compile libcxx into intermittent library
# place install rule

# Use an external project to place the headers in the collector-dir
include (ExternalProject)
ExternalProject_Add(libcxx_includes
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/libcxx/include ${OE_INCDIR}/openenclave/libcxx
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libcxx/include/__config ${OE_INCDIR}/openenclave/libcxx/__config_original
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/__config ${OE_INCDIR}/openenclave/libcxx/__config
    INSTALL_COMMAND ""
    )

# build sources

add_library(libcxx STATIC
    __dso_handle.cpp

    libcxx/src/algorithm.cpp
    libcxx/src/any.cpp
    libcxx/src/bind.cpp
    libcxx/src/chrono.cpp
    libcxx/src/condition_variable.cpp
    libcxx/src/debug.cpp
    libcxx/src/exception.cpp
    libcxx/src/functional.cpp
    libcxx/src/future.cpp
    libcxx/src/hash.cpp
    libcxx/src/ios.cpp
    libcxx/src/iostream.cpp
    libcxx/src/locale.cpp
    libcxx/src/memory.cpp
    libcxx/src/mutex.cpp
    libcxx/src/new.cpp
    libcxx/src/optional.cpp
    libcxx/src/random.cpp
    libcxx/src/regex.cpp
    libcxx/src/shared_mutex.cpp
    libcxx/src/stdexcept.cpp
    libcxx/src/string.cpp
    libcxx/src/strstream.cpp
    libcxx/src/system_error.cpp
    libcxx/src/thread.cpp
    libcxx/src/typeinfo.cpp
    libcxx/src/utility.cpp
    libcxx/src/valarray.cpp
    libcxx/src/variant.cpp
    libcxx/src/vector.cpp
    )

target_compile_options(libcxx PRIVATE -std=c++14)
target_compile_definitions(libcxx PRIVATE
    -DLIBCXXRT
    -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE
    -D_LIBCPP_BUILDING_LIBRARY
    -DOE_LIBC_SUPPRESS_DEPRECATIONS
    )

# need the LIBCXX_CXX headers placed
add_dependencies(libcxx libcxx_includes)
# this project and its dependents require include/libcxx in the include path
target_include_directories(libcxx PUBLIC
    $<BUILD_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${OE_INCDIR}/openenclave/libcxx>>
    $<INSTALL_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/libcxx>>
    )

# this project (and is dependents) require the LIBC includes
target_link_libraries(libcxx PUBLIC oelibc)
# If we built an OBJECT library, we would want to do the following, though CMake does not allow
#  using target_link_libraries on an OBJECT lib (yet?):
#add_dependencies(libcxx oelibc)
#target_include_directories(libcxx PUBLIC ${OE_INCDIR}/libc)

# when building this project, we also need a number of internal includes
target_include_directories(libcxx PRIVATE libcxx/src)
target_include_directories(libcxx PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/src)

# install target just to propagate include-location, but not the archive iself
install(TARGETS libcxx EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

install(DIRECTORY ${OE_INCDIR}/openenclave/libcxx
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
