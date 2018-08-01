This directory runs tests relating to debug-mode and signed enclaves.

There are 8 different cases for debug/signed enclaves which depend on the following settings:
  - If the enclave is signed or unsigned.
  - If the enclave is debug mode or not.
  - If the flags parameter in `oe_create_enclave` has the debug bit set or not.
  
The table demonstrates the expected value of the 8 cases:

| Enclave Signed? | Enclave Debug? | Flags Debug Bit Set? | Result                |
| --------------- |----------------| ---------------------|-----------------------|
| Yes             | Yes            | Yes                  | Success               |
| Yes             | Yes            | No                   | Sucesss*              |
| Yes             | No             | Yes                  | Fail (OE_DOWNGRADE)   |
| Yes             | No             | No                   | Success*              |
| No              | Yes            | Yes                  | Success**             |
| No              | Yes            | No                   | Fail**                |
| No              | No             | Yes                  | Fail (OE_DOWNGRADE)** |
| No              | No             | No                   | Fail**                |

\* Requires Coffeelake (SGX-1 with Flexible Launch Control)  
\*\* Requires Linux

Note that these tests are skipped when run in simulation mode.
