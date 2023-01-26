# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../compiler_rt.edl)

add_custom_command(
  OUTPUT compiler_rt_t.h compiler_rt_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# Fetch all the unit test files from LLVM's test suite.
# The list of files will rarely change during development. It will change when
# compiler-rt is upgraded. Therefore, it is OK to use GLOB to gather the list.
file(GLOB TEST_FILES
     "../../../3rdparty/compiler-rt/compiler-rt/test/builtins/Unit/*.c"
     "../../../3rdparty/compiler-rt/compiler-rt/test/builtins/Unit/*.cxx")

list(LENGTH TEST_FILES NUM_TEST_FILES)
# Update the expected number of tests every time compiler-rt is updated.
set(EXPECTED_NUM_TEST_FILES 182)
if (NOT ${NUM_TEST_FILES} EQUAL ${EXPECTED_NUM_TEST_FILES})
  message(
    FATAL_ERROR
      "Expecting ${EXPECTED_NUM_TEST_FILES} compiler-rt test files. Found ${NUM_TEST_FILES}"
  )
endif ()

# List of tests that work within enclaves. Most do.
set(SUPPORTED_TESTS "")

# The following tests don't work withn enclaves since they rely on
# functionality that OE doesn't support. E.g: executable stack.
set(IGNORE_LIST "clear_cache_test" "cpu_model_test" "gcc_personality_test"
                "gcc_personality_test_helper" "enable_execute_stack_test")

if (OE_TRUSTZONE)
  # The following functions are not available in AARCH64.
  list(APPEND IGNORE_LIST "divxc3_test" "mulxc3_test" "powixf2_test")
endif ()

set(PROTOTYPES "")
set(CALLS "")

foreach (TEST IN LISTS TEST_FILES)
  get_filename_component(NAME "${TEST}" NAME_WE)
  get_filename_component(EXT "${TEST}" EXT)

  # Check whether the test needs to be ignored.
  list(FIND IGNORE_LIST ${NAME} FOUND)
  if (${FOUND} GREATER "-1")
    continue()
  endif ()

  # When compiling each test file,
  #   - rename main to ${NAME}_main. This function will be called from
  #     generated test.c.
  #   - Prefix ${NAME} to identifiers that are also used in other test files.
  set(COMPILE_FLAGS
      "-Dmain=${NAME}_main -Dassumption_1=${NAME}_assumption_1 \
    -Dassumption_2=${NAME}_assumption_2 -Dassumption_3=${NAME}_assumption_3 \
    -Dclassify=${NAME}_classify -Dx=${NAME}_x -Dcases=${NAME}_cases \
    -Dtests=${NAME}_tests -Dnaive_popcount=${NAME}_naive_popcount \
    -Dnaive_parity=${NAME}_naive_parity")

  if (${NAME} MATCHES "extendhfsf2")
    # This testcase fails when compiled with optimizations.
    # The same failure can be reproduced outside OE by doing:
    #    clang-11 ../../../lib/builtins/extendhfsf2.c extendhfsf2_test.c
    #          -fpic -O2 -fno-builtin -ffreestanding
    #    ./a.out
    # Therefore disable optimizations for this testcase.
    # due to compiler optimizations.
    string(APPEND COMPILE_FLAGS " -O0")
  endif ()

  set_source_files_properties(${TEST} PROPERTIES COMPILE_FLAGS
                                                 "${COMPILE_FLAGS}")

  # Add test to list of supported tests.
  list(APPEND SUPPORTED_TESTS ${TEST})

  string(APPEND CALLS "    OE_TEST(${NAME}_main() == 0);\n\n")
  if (${EXT} STREQUAL ".c")
    string(APPEND PROTOTYPES "extern \"C\" int ${NAME}_main(void);\n")
  else ()
    string(APPEND PROTOTYPES "int ${NAME}_main();\n")
  endif ()
endforeach ()

# Emit a file test.c that calls each individual test.
set(TEST_CPP "${CMAKE_CURRENT_BINARY_DIR}/test.cpp")
file(WRITE "${TEST_CPP}" "#include <openenclave/enclave.h>\n")
file(APPEND "${TEST_CPP}" "#include <openenclave/internal/tests.h>\n\n")

# Emit prototypes
file(APPEND "${TEST_CPP}" "${PROTOTYPES}")
file(APPEND "${TEST_CPP}" "extern \"C\" void run_tests()\n{\n\n")
file(APPEND "${TEST_CPP}" "${CALLS}")

# Close test.cpp.
file(APPEND "${TEST_CPP}" "}\n\n")
file(APPEND "${TEST_CPP}"
     "extern \"C\" int enc_test() { run_tests(); return 0; }")

add_enclave(
  TARGET
  compiler_rt_enc
  UUID
  d0a1a92a-cfc5-4563-b9d4-57cf526a839d
  SOURCES
  enc.c
  test.cpp
  ${SUPPORTED_TESTS}
  ${CMAKE_CURRENT_BINARY_DIR}/compiler_rt_t.c)

enclave_include_directories(
  compiler_rt_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  "${PROJECT_SOURCE_DIR}/3rdparty/compiler-rt/compiler-rt/lib/builtins")

maybe_build_using_clangw(compiler_rt_enc)

enclave_compile_options(compiler_rt_enc PRIVATE -Wno-error)
enclave_link_libraries(compiler_rt_enc oelibcxx oelibc)
