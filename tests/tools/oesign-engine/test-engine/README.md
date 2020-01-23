# Oesign Test Engine

The oesign test engine allows Open Enclave to validate openssl engine functionality
in oesign without depending on an external setup step.  The test engine is a real, functional
openssl engine, but offers only the functionality needed to offer
a single signing key to oesign to test the oesign paths.

If oesign is modified to use additional engine functionality, for example engine-based
signing and sealing, the test-engine will require modification.
