# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oeverify oeverify.c)

target_include_directories(oeverify PRIVATE ${PROJECT_SOURCE_DIR}/include)

# By default, link against standard oehostverify (production certificates only)
# To enable pre-production certificate support, set OE_VERIFY_USE_PRERELEASE=ON
option(OE_VERIFY_USE_PRERELEASE
       "Build oeverify with pre-production certificate support" OFF)

if (OE_VERIFY_USE_PRERELEASE)
  message(STATUS "Building oeverify with pre-production certificate support")
  target_compile_definitions(oeverify PRIVATE OEUTIL_TCB_ALLOW_ANY_ROOT_KEY)
  target_link_libraries(oeverify oehostverify_prerelease)
else ()
  message(STATUS "Building oeverify with production certificates only")
  target_link_libraries(oeverify oehostverify)
endif ()

# assemble into proper collector dir
set_property(TARGET oeverify PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(
  TARGETS oeverify
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  COMPONENT OEHOSTVERIFY)
