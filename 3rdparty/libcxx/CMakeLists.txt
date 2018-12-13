# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include (ExternalProject)
ExternalProject_Add(libcxx_includes
  DOWNLOAD_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_LIST_DIR}/libcxx/include ${OE_INCDIR}/openenclave/libcxx
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libcxx/include/__config ${OE_INCDIR}/openenclave/libcxx/__config_original
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/__config ${OE_INCDIR}/openenclave/libcxx/__config
  INSTALL_COMMAND "")

add_library(libcxx OBJECT
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
  libcxx/src/vector.cpp)

add_dependencies(libcxx libcxx_includes)

set_target_properties(libcxx PROPERTIES
  POSITION_INDEPENDENT_CODE ON)

target_compile_definitions(libcxx
  PRIVATE
  -DLIBCXXRT
  -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE
  -D_LIBCPP_BUILDING_LIBRARY
  -DOE_LIBC_SUPPRESS_DEPRECATIONS)

target_link_libraries(libcxx PUBLIC oelibc)

target_include_directories(libcxx
  PUBLIC
  $<BUILD_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${OE_INCDIR}/openenclave/libcxx>>
  $<INSTALL_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/libcxx>>
  PRIVATE
  libcxx/src
  ../libcxxrt/libcxxrt/src)

# Prevent warnings treated as error
set_source_files_properties(
  libcxx/src/locale.cpp
  PROPERTIES COMPILE_FLAGS "-Wno-conversion"
)

set_source_files_properties(
  libcxx/src/system_error.cpp
  PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter"
)

install(TARGETS libcxx EXPORT openenclave-targets
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

install(DIRECTORY ${OE_INCDIR}/openenclave/libcxx
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
