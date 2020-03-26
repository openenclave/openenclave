# EDL Bits Headers

In order to allow more control over which OCalls are made by an enclave
application, all EDL files used by the OE runtime are published to be
imported by user EDL. In order to support this, some internal types must be
published.

These are published with no guarantees of stability and are not part of the
public API surface. They are only intended to be used internally by the OE
runtime.
