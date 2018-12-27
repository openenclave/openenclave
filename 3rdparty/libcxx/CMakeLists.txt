# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(LIBCXX_INCLUDES ${OE_INCDIR}/openenclave/libcxx)

include (ExternalProject)
ExternalProject_Add(libcxx_includes
  DOWNLOAD_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_LIST_DIR}/libcxx/include ${LIBCXX_INCLUDES}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libcxx/include/__config ${LIBCXX_INCLUDES}/__config_original
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/__config ${LIBCXX_INCLUDES}/__config
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

# Configure clangw before turning off warnings.
if (USE_CLANGW)
  build_using_clangw(libcxx)
endif()

target_compile_options(libcxx PRIVATE -Wno-error)

target_compile_definitions(libcxx
  PRIVATE
  -DLIBCXXRT
  -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE
  -D_LIBCPP_BUILDING_LIBRARY
  -DOE_LIBC_SUPPRESS_DEPRECATIONS)

target_link_libraries(libcxx PUBLIC oelibc)

target_include_directories(libcxx
  PUBLIC
  $<BUILD_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${LIBCXX_INCLUDES}>>
  $<INSTALL_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/libcxx>>
  PRIVATE
  libcxx/src
  ../libcxxrt/libcxxrt/src)

install(TARGETS libcxx EXPORT openenclave-targets)

install(DIRECTORY ${LIBCXX_INCLUDES}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
