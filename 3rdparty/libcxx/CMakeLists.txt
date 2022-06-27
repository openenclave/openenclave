# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(FetchContent)
FetchContent_Declare(
  libcxx_sources
  SOURCE_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/libcxx"
  URL https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/libcxx-10.0.1.src.tar.xz
  URL_HASH
    SHA256=def674535f22f83131353b3c382ccebfef4ba6a35c488bdb76f10b68b25be86c)

FetchContent_GetProperties(libcxx_sources)
if (NOT libcxx_sources_POPULATED)
  FetchContent_Populate(libcxx_sources)
endif ()

include(ExternalProject)
ExternalProject_Add(
  libcxx_includes
  DOWNLOAD_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_LIST_DIR}/libcxx/include ${LIBCXX_INCLUDES}
  COMMAND
    ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/libcxx/include/__config
    ${LIBCXX_INCLUDES}/__config_original
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/__config
          ${LIBCXX_INCLUDES}/__config
  INSTALL_COMMAND "")

set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${LIBCXX_INCLUDES})

add_enclave_library(
  libcxx
  OBJECT
  __dso_handle.cpp
  libcxx/src/algorithm.cpp
  libcxx/src/any.cpp
  libcxx/src/bind.cpp
  libcxx/src/charconv.cpp
  libcxx/src/chrono.cpp
  libcxx/src/condition_variable.cpp
  libcxx/src/condition_variable_destructor.cpp
  libcxx/src/debug.cpp
  libcxx/src/exception.cpp
  libcxx/src/filesystem/operations.cpp
  libcxx/src/filesystem/int128_builtins.cpp
  libcxx/src/filesystem/directory_iterator.cpp
  libcxx/src/functional.cpp
  libcxx/src/future.cpp
  libcxx/src/hash.cpp
  libcxx/src/ios.cpp
  libcxx/src/iostream.cpp
  libcxx/src/locale.cpp
  libcxx/src/memory.cpp
  libcxx/src/mutex.cpp
  libcxx/src/mutex_destructor.cpp
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

# When speculative load hardening is enabled on future.cpp with Clang-10 compiler
# future and promise constructs of C++ are not working as expected and resulting in
# SIGBUS errors. Disable compiler optimizations till this issue is addressed
# in clang-10 compiler codebase.
if (WIN32 OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
  set_source_files_properties(libcxx/src/future.cpp PROPERTIES COMPILE_FLAGS
                                                               -O0)
endif ()

maybe_build_using_clangw(libcxx)

add_enclave_dependencies(libcxx libcxx_includes)

enclave_compile_options(libcxx PRIVATE -Wno-error)

enclave_compile_definitions(
  libcxx PRIVATE -DLIBCXXRT -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE
  -D_LIBCPP_BUILDING_LIBRARY -DOE_LIBC_SUPPRESS_DEPRECATIONS)

enclave_include_directories(libcxx PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(libcxx PUBLIC oelibc)

# NOTE: The `PUBLIC` headers for `libcxx` are actually added to
# `oelibc_includes`, this is necessary to get the ordering correct.
# See `../musl/CMakeLists.txt` for more details.
enclave_include_directories(libcxx PRIVATE libcxx/src ../libcxxrt/libcxxrt/src)

install_enclaves(TARGETS libcxx EXPORT openenclave-targets)

install(DIRECTORY ${LIBCXX_INCLUDES}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
