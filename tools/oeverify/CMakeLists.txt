# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oeverify oeverify.c)

target_include_directories(oeverify PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(oeverify oehostverify)

# assemble into proper collector dir
set_property(TARGET oeverify PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(
  TARGETS oeverify
  DESTINATION ${CMAKE_INSTALL_BINDIR}
  COMPONENT OEHOSTVERIFY)
