# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(oesgx oesgx.c)

target_include_directories(oesgx PRIVATE ${PROJECT_SOURCE_DIR}/include)

# assemble into proper collector dir
set_property(TARGET oesgx PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

if (WIN32)
  set_target_properties(oesgx PROPERTIES LINK_FLAGS "/Guard:CF")
endif ()

# install rule
install(TARGETS oesgx DESTINATION ${CMAKE_INSTALL_BINDIR})
