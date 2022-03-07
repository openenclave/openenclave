# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  add_subdirectory(td_state)
  add_subdirectory(thread_interrupt)
endif ()

add_subdirectory(extra_data)
