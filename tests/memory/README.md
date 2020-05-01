This directory tests enclave memory management with the following tests:
  - Checking that basic uses of malloc and free work.
  - Checking that malloc returns pointers within the enclave boundary.
  - Stress test the malloc family set of functions by rapid allocation
    and freeing.
  - Stress test the malloc family functions by rapid allocation and freeing
    in a multi-threaded context.
