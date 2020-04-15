# Exclude System EDL test

This is a temporary test to ensure that an enclave application builds properly
when the SDK is compiled with `-DCOMPILE_SYSTEM_EDL=OFF`.

In the future all other tests should be updated to import system EDL in their own
EDL files and this test should be removed.
