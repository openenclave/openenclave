# oeverify

This directory contains the oeverify tool, which can verify remote attestation evidence and attestation certificates.

For example:

```bash
$ /opt/openenclave/bin/oeverify -r <path/to/evidence> -e </path/to/endorsement> [-f <evidence_format>]
Verifying evidence ...
Claims:
...
Evidence verification succeeded (0).
```
