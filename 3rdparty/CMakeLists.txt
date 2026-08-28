# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# NOTE: This is set here so that both `libcxx` and `musl` can use it
# without setting it twice. This is necessary due to an odd dependency
# between the two targets. See their respective CMake files for more
# details.
set(LIBCXX_INCLUDES ${OE_INCDIR}/openenclave/libcxx)

add_subdirectory(compiler-rt)
add_subdirectory(dlmalloc)
add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
add_subdirectory(mbedtls)

if (OE_SGX AND COMPILER_SUPPORTS_SNMALLOC)
  # snmalloc is most useful in multi-threaded enclaves. Currently, only
  # SGX enclaves can be multi-threaded.
  add_subdirectory(snmalloc)
endif ()

if (BUILD_OPENSSL)
  add_subdirectory(openssl)
  add_subdirectory(symcrypt_engine)
  add_subdirectory(symcrypt_provider)
endif ()
