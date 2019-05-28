oeedger8r tests
===============

Test constructs supported by `oeedger8r`.

- **edltestutils.h**
  1. *Purpose*: Contains utilities to lock down types of the marshalling struct and to track memory allocation during parameter marshaling.

- **mytypes.h**
  1. *Purpose*: Contains types used for testing "foreign" types in EDL.

- **array.edl**
  1. *Purpose*: Test ecalls and ocalls for in, in-out, out compinations for single, double, triple dimensional arrays
      for all basic types.
  2. *enc/teststring.cpp* : Defines ecall implementations. Also `test_array_edl_ocalls` function to test ocalls.
  3. *host/teststring.cpp*: Defines ocall implementations. Also `test_array_edl_ecalls` function to test ecalls.

- **basic.edl**
  1. *Purpose* : Test ecalls and ocalls using basic types as parameters and return types.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also `test_basic_edl_ocalls` function to test ocalls.
  3. *host/testbasic.cpp*: Defines ocall implementations. Also `test_basic_edl_ecalls` function to test ecalls.

- **enum.edl**
  1. *Purpose* : Test ecalls and ocalls for enum type defined in EDL. Test pass-by value, return, and all pointer semantics.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also `test_enum_edl_ocalls` function to test ocalls.
  3. *host/testbasic.cpp*: Defines ocall implementations. Also `test_enum_edl_ecalls` function to test ecalls.

- **errno.edl**
  1. *Purpose*: Test propagate_errno annotation. Lock down initial value of errno, propagation/non-propagation of errno value from host to enclave depending on annotation, generation/non-generation of _ocall_errno field.
  2. *enc/testerrno.cpp* : Defines ecall implementations.
  3. *host/testerrno.cpp* : Defines ocall implementations.

- **foreign.edl**
  1. *Purpose* : Test ecalls and ocalls for foreign types. Foreign type is a type that is defined outside of EDL and is not a primitive type. Test pass by value and `isary` attributes. Also when an explicit `*` is used, test all pointer semantics.
     Also if `*` is not used but `isptr` attribute is specified (say for `typedef int * my_type`), then pointer semantics are allowed.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also `test_foreign_edl_ocalls` function to test ocalls.
  3. *host/testbasic.cpp*: Defines ocall implementations. Also `test_foreign_edl_ecalls` function to test ecalls.

- **pointer.edl**
  1. *Purpose* : Test ecalls and ocalls for pointer parameters types. Test in, in-out, out attributes for all primitive types. By default the parameter is expected to point to one element. If `count` attribute is specified, then the parameter is expected to point to count number of elements. If `size` attribute is specified then the parameter is expected to point to `size` bytes whether size is a multiple of element-size or not. Also test `user_check` attribute.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also `test_foreign_edl_ocalls` function to test ocalls.
  3. *host/testbasic.cpp*: Defines ocall implementations. Also `test_foreign_edl_ecalls` function to test ecalls.

- **string.edl**
  1. *Purpose*: Test ecalls and ocalls for `[string, in]`, `[string, in, out]` attribute combinations.
  2. *enc/teststring.cpp* : Defines ecall implementations. Also `test_string_edl_ocalls` function to test ocalls.
  3. *host/teststring.cpp*: Defines ocall implementations. Also `test_string_edl_ecalls` function to test ecalls.

- **struct.edl**
  1. *Purpose* : Test ecalls and ocalls for struct type defined in EDL. Test pass-by value, return, and all pointer semantics.
     Also test nesting of structs.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also `test_struct_edl_ocalls` function to test ocalls.
  3. *host/testbasic.cpp*: Defines ocall implementations. Also `test_struct_edl_ecalls` function to test ecalls.
