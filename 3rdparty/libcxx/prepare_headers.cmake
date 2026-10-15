# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

foreach (argument SOURCE_DIR OUTPUT_DIR CONFIG_HEADER GIT_EXECUTABLE)
  if (NOT DEFINED ${argument})
    message(FATAL_ERROR "Missing header preparation argument: ${argument}")
  endif ()
endforeach ()
if (NOT DEFINED PATCH_FILES)
  include("${PATCH_DIR}/series.cmake")
  set(PATCH_FILES ${LIBCXX_HEADER_PATCHES})
endif ()
if ("${SOURCE_DIR}" STREQUAL "${OUTPUT_DIR}" OR OUTPUT_DIR STREQUAL "")
  message(
    FATAL_ERROR "Collected headers must be separate from upstream sources")
endif ()

# Always start from pristine headers. No reverse-patch heuristics or repository
# status checks are needed, and removing a patch restores the original header.
# Keep the previous collected headers intact if any patch fails to apply.
set(staging "${OUTPUT_DIR}.staging")
file(REMOVE_RECURSE "${staging}")
file(MAKE_DIRECTORY "${staging}/include" "${staging}/patches")
file(COPY "${SOURCE_DIR}/" DESTINATION "${staging}/include")

set(patches)
foreach (patch IN LISTS PATCH_FILES)
  get_filename_component(name "${patch}" NAME)
  # Patches may be checked out with CRLF on Windows; upstream archive headers
  # use LF. Normalize patch transport only, never alter the hunk contents.
  file(READ "${patch}" contents)
  string(REPLACE "\r\n" "\n" contents "${contents}")
  # Native Windows CMake may write CRLF with file(WRITE), even after the
  # in-memory normalization above. Substitute once through a template so
  # literal @variables@ and ${variables} inside patches remain untouched.
  configure_file("${CMAKE_CURRENT_LIST_DIR}/patch_contents.in"
                 "${staging}/patches/${name}" @ONLY NEWLINE_STYLE UNIX)
  list(APPEND patches "${staging}/patches/${name}")
endforeach ()

if (patches)
  foreach (operation check apply)
    set(options --no-index --whitespace=error-all)
    if (operation STREQUAL "check")
      list(APPEND options --check)
    endif ()
    execute_process(
      COMMAND
        "${CMAKE_COMMAND}" -E env --unset=GIT_DIR --unset=GIT_WORK_TREE
        --unset=GIT_INDEX_FILE "GIT_CEILING_DIRECTORIES=${staging}"
        "${GIT_EXECUTABLE}" -c core.autocrlf=false -c core.eol=lf apply
        ${options} ${patches}
      WORKING_DIRECTORY "${staging}/include"
      RESULT_VARIABLE result
      ERROR_VARIABLE diagnostic)
    if (NOT result EQUAL 0)
      file(REMOVE_RECURSE "${staging}")
      message(FATAL_ERROR "libc++ patch ${operation} failed: ${diagnostic}")
    endif ()
  endforeach ()
endif ()

configure_file("${staging}/include/__config"
               "${staging}/include/__config_original" COPYONLY)
configure_file("${CONFIG_HEADER}" "${staging}/include/__config" COPYONLY)
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E copy_directory "${staging}/include"
          "${OUTPUT_DIR}" RESULT_VARIABLE result)
file(REMOVE_RECURSE "${staging}")
if (NOT result EQUAL 0)
  message(FATAL_ERROR "Failed to copy prepared libc++ headers to ${OUTPUT_DIR}")
endif ()
