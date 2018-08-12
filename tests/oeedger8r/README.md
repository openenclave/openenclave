oeedger8r tests
=====================

Test constructs supported by oeedger8r .

- **edltestutils.h**
  1. *Purpose*: Contains utilities to lock down types of the marshalling struct and to track memory allocation during parameter marshaling.

- **basic.edl**
  1. *Purpose* : Test ecalls and ocalls using basic types as parameters and return types.
  2. *enc/testbasic.cpp* : Defines ecall implementations. Also test_basic_edl_ocalls function to test ocalls.
  3. *host/testbasic.cpp*: Defines Ocall implementations. Also test_basic_edl_ecalls function to test ecalls.
