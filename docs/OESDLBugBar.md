# Open Enclave SDL (Security Development Lifecycle) Bug Bar

The information listed in this “bug bar” is intended to help Open Enclave SDK developers to triage bugs and determine bug severity in terms of security for all types of Trusted Execution Environments (TEEs) supported by Open Enclave. It is highly recommended to fix all known bugs with critical, important, or moderate severity prior to release. This bug bar should also be used during the triage meeting to evaluate bugs for any security implication and tag accordingly.

The bug bar describes different severities for the bugs affecting TEEs. TEEs are specifically designed to provide: Confidentiality, Integrity, Authenticity and, to a limited extent, Authorization. There is a security boundary between a TEE and the rest of the system, which needs to be defended against any bugs that lead to compromising the TEE purpose. Anything within a TEE should never be accessible or modified from outside.

## Open Enclave – Severity Type Pivot
-------------------------------------

* ### **Critical**
  Information Disclosure
  * Any cases where an attacker can reveal arbitrary information within a TEE that was not intended or designed to be exposed
      * Example:
        * Unintentional read access to memory contents of an enclave from outside (application, OS kernel, Hypervisor or other enclave)

  Tampering
  * Any modification of TEE code or data by untrusted entity outside of the TEE
    * Example:
      * Modifying the enclave image in plain text in such a way that measurements doesn't change

  Elevation of Privilege  
  * Any cases where an attacker can bypass the TEE security boundary and execute unintended code within the TEE context
    * Examples:
      * Any exploitable memory-safety issues inside an enclave that are induced from outside of enclave
      * Attacker able to start enclave execution at location other than defined enclave entry point
      * Executing non-enclave code in the context of an enclave thread
       
-------------

* ### **Important**
  Information Disclosure
  * Disclosing TEE memory contents to outside of the TEE and attacker doesn't know or control address of the data.
    * Examples:
      * OCALLS passing uninitialized memory from enclave to outside
      * Unintended writes of plaintext enclave memory to shared memory
------------

* ### **Moderate**
  Elevation Of Privilege
  * Any access to untrusted memory by TEE in an unsafe manner
    * Example:
      * Any untrusted memory that is accessed multiple times (multiple fetch) without copying it to enclave memory
------------

* ### **Low**
  Information Disclosure
  * Any exposure of TEE data, that are considered as non-secrets, to outside of TEE
    * Examples:
      * Reads of enclave copy of data from shared memory
      * Unintended writes of zeroed enclave memory to shared memory
------------