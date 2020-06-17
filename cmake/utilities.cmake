# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Utility to ensure specific submodules are present.
function (check_submodule_not_empty path)
  file(GLOB submodule_files "${path}/*")
  list(LENGTH submodule_files number)
  if (${number} EQUAL 0)
    message(
      FATAL_ERROR
        "Submodule ${path} is empty. You can initialize the submodule now with \
         'git submodule update --recursive --init',\
         or during 'git clone' by passing '--recursive'.")
  endif ()
endfunction ()

# Utility to apply patches.
# Note that each patch should only apply to a single file.
# The naming rule of the patch should be "file_name.patch".
function (apply_patches patches_path target_path)
  file(GLOB PATCHES ${patches_path}/*.patch)
  if (NOT PATCHES)
    return()
  endif ()

  foreach (PATCH ${PATCHES})
    # Obtain the file name to be patched.
    get_filename_component(PATCH_NAME ${PATCH} NAME)
    string(REPLACE ".patch" "" PATCHED_FILE ${PATCH_NAME})

    # Check if the target file is patched already.
    execute_process(
      COMMAND git status -s
      OUTPUT_VARIABLE STATUS
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${target_path})
    if (STATUS MATCHES ${PATCHED_FILE})
      message("-- ${PATCHED_FILE} is patched already - skip")
      continue()
    endif ()

    # Apply the patch.
    message("-- Applying the patch ${PATCH_NAME}")
    execute_process(COMMAND git apply ${PATCH}
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
  endforeach ()
endfunction ()
