# Signing a Build With OpenSSL Engines

OpenSSL allows extensions called "engines" to perform the generation of keys, signing and encryption.
Engines are useful. They can be used to allow hardware offload of encryption duties, or improved 
encapsulation of secrets. Use of engines is required in some build systems as a way to avoid the
storage of keys in plain text .pem files.

oesign has been equipped with the ability to specify engines in the enclave signing process. In order
to use the engine, the command line syntax has been extended.
```
oesign sign --enclave-image ENCLAVE_IMAGE --config-file CONFIG_FILE --engine engine-NAME -load-path engine-LOAD-PATH-key KEY-ID

```

## Engines 

The concept of an engine was added to OpenSSL starting with 0.9.6. There are built in engine implementations
implementations for
- Microsoft CryptoAPI
- VIA Padlock
- nCipher CHIL
and a api for controlling dynamically bound engines which are bound from shared libraries at runtime via either program logic
or configuration files. 

The openssl commnd line utility can show available engines via the "engine" command.
```
# openssl engine
(rdrand) Intel RDRAND engine
(dynamic) Dynamic engine loading support

```
Of particular interest is the "dynamic" engine, which allow dynamic plugins to perform encryption duties. 
These objects allow a plugin mechanism for implementations of cryptographic algorithms and can be statically linked in the
OpenSSL library at compile-time or dynamically loaded at run-time in and out of the running application 
with low overhead from external binary shared objects implementing the engine API using special built-in engine
called “dynamic”. 

Dynamic engines are particularly interesting due to the flexibility they provide: 

- They allow sensitive encryption data structures, such as private key bits, or data to be signed, to be kept out of publicly viewable memory, 
  so reduce the risk of leaked secrets in case of a security breach. The actual secrets may be kept in enclave memory or another dedicated host service.

- They allow sensitive processes and algorithms to be divided from the overall project and hidden from other organizations.

- They reduce the memory impact of OpenSSL, by avoiding statically linking support for unneeded hardware or features at
  compile-time in favor of system configuration or automatically probing for supported devices at run-time and dynamically
  loading only the required cryptographic modules.

- They allow the developer or system administrator to replace compiled in OpenSSL functionality in case of bugs, 
  known vulnerabilities or sub-optimal performances with more appropriate alternative implementations while maintaining compatibility
  with existing applications.

- They provide an alternative in case of issues with the OpenSSL core development team or distro vendor decision-making process, decoupling
  the decision to adopt the OpenSSL library from the choice of individual cryptosystem implementations, without incurring the 
  costs of maintaining a fork of the OpenSSL project or patchsets, while also providing transparent binary compatibility with existing applications; 

- They allow hardware vendors to release self-contained plugins to leverage advanced hardware concepts, such as GPU compute, FPLAs, or
  quantum based encrytion which can work then with existing applications based on OpenSSL, keeping their software outside
 of the main OpenSSL codebase.

- They allow backporting newer crypto systems in previous versions of the OpenSSL library and existing applications based on it.

- They allow a straightforward method of protyping and deploying new crypto systems or new implementations for already compiled-in 
  cryptosystems to the OpenSSL library, providing convenient way to test and benchmark new software implementations in a real-world context.

- They offer a greater degree of freedom from the OpenSSL project toolchain, allowing developers to use different programming
  languages and build systems, potentially lowering the development and maintenance costs for developing plugin alternative
  implementations or new functionality.

- They offer flexibility to solve licensing issues. 

  Currently the OpenSSL project is released under a "dual license" scheme, under the OpenSSL License,
  (a derivative of the Apache License 1.0) and the SSLeay License (similar to a 4-clause BSD License). OpenSSL is in the process of 
  transitioning to the Apache License 2.0. Contributors are thus forced to release their work under these licenses, which may conflict
  with other applicable licenses especially when reusing code from projects released under a proprietary license or an incompatible copyleft license. 

  Being objects dynamically loaded at runtime, engines can benefit from usually more flexible licensing requirements, providing bridge 
  towards software released under different licenses.

## Engine internal operation

The cryptographic functionality that can be provided by an engine implementation includes the following abstractions:
(1) RSA_METHOD, DSA_METHOD, DH_METHOD, EC_METHOD; providing alternative RSA/DSA/etc. implementations; 
(2) RAND_METHOD: providing alternative (pseudo-)random number generation implementations;
(3) EVP_CIPHER: providing alternative (symmetric) cipher algorithms;
(4) EVP_MD: providing alternative message digest algorithms;
(5) EVP_PKEY: providing alternative public key algorithms.

At the highest level of abstraction, a dynamic engine can be split into two functional blocks.

One block contains all the alternative implementations for the cryptosystems provided by the engine. This part mainly consists of a
collection of structs for each cryptosystem, each linking to the actual functions implementing its operations.

For example, an EVP_MD message digest struct would reference the actual init(), update(), and final() functions implementing
the OpenSSL message digest streaming API, in addition to some utility functions allowing the OpenSSL library to cleanly handle, 
clone and destroy instances of the provided message digest implementation. Every such struct would be individually registered against
the OpenSSL library during the bind() process, and structs of the same kind (e.g. all the EVP_MD structs, all the EVP_PKEY_meth structs, etc.)
are glued together by functions registered in the engine object that allow the OpenSSL library to query the engine for lists of
provided algorithms or a specific algorithm indexed by NID.

The other block contains the bind() method and the initialization and deinitialization functions. 
- The bind() method is called by the OpenSSL built-in dynamic engine upon load and is used to set the internal state of the 
engine object and allocate needed resources, to set its id and name, and the pointers to the init(), finish(), and destroy() functions. 

- The init() function is called to derive a fully initialized functional reference to the engine from a structural reference.

- The finish() function is called when releasing an engine functional reference, to freeup any resource allocated to it

- The Destroy() function is called upon unloading the engine, when the last structural reference to it is released, to cleanly free any
resource allocated upon loading it into memory.



   
