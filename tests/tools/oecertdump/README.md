oecertdump
=====

oecertdump is a utility that generates and validates report and certificates.
Generation and validation logs are save to a log file specified by --out option.
Default log filename is "oecertdump_out.log".

Usage: oecertdump ENCLAVE_PATH Options

where Options are:
    --out FILENAME        : specify output filename.

Example: host/oecertdump enc/oecertdump_enc --out myoutput.log