oeedger8r tests
=====================

Test constructs supported by oeedger8r .

- **edltestutils.h**
  1. *Purpose*: Contains utilities to lock down types of the marshalling struct and to track memory allocation during parameter marshaling.

- **basic.edl**
  1. *Purpose* : Test ecalls and ocalls using basic types as parameters and return types.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also test_basic_edl_ocalls function to test ocalls.
  3. *host/testbasic.cpp*: Defines ocall implementations. Also test_basic_edl_ecalls function to test ecalls.

- **string.edl**
  1. *Purpose*: Test ecalls and ocalls for [string, in], [string, in, out] attribute combinations.
  2. *enc/teststring.cpp* : Defines ecall implementations. Also test_string_edl_ocalls function to test ocalls.
  3. *host/teststring.cpp*: Defines ocall implementations. Also test_string_edl_ecalls function to test ecalls.
  