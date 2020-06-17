oecertdump
=====

oecertdump is a utility that generates and validates reports and certificates.
Generation and validation logs are saved to a log file specified by the --out option.
Default log filename is "oecertdump_out.log".

Usage: oecertdump ENCLAVE_PATH Options

where Options are:
    --out FILENAME        : specify output filename.
    --type TYPE           : report (default), ec, or rsa (generate a cerfiticate signed with ec or rsa key)
    --verbose             : print every field in a report or a certificate

Example: host/oecertdump enc/oecertdump_enc --out myoutput.log --type report --verbose

If the validation succeeds, oecertdump returns 0 and prints success message to stdout. For example,
    "oecertdump succeeded. Log file oecertdump_out.log created."

If the validation fails, oecertdump returns non zero and prints failure message to stdout. For example,
    "Failed to process parameters."