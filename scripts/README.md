scripts
=======

This directory contains the following scripts.

- format-code - Formats Open Enclave C/C++ code in the source tree

- install-prereqs - Installs packages needed for the Open Enclave project

- check-license - Prints a list of OE sources without a license header

- cxx-check - Checks sources first with the C++ compiler and then with C. To 
  enable use of this script, configure cmake as follows. 
  
  ``` 
  cmake -DENABLE_CXX_CHECK=1 ..
  ```

