OEUTIL
=====

`oeutil` supports the following OE commands, which can be abbreviated to a prefix:

    1. generate-evidence

Usage: `oeutil <command> <options>`

-----

## oeutil generate-evidence

`oeutil generate-evidence` can generate the following files in binary format, or dump them in readable text, and verify them:

 1. Self-signed certificates (in der format) used for remote attestation over TLS.
 2. An OE report.
 3. An OE evidence.
 4. An endorsement for OE report/evidence.

For certificates, the user can pass in the public/private key.
`oeutil generate-evidence` is not suitable for production use.

Usage: `oeutil generate-evidence <options>`

where `options` are:

    -f, --format <format_option>: generate evidence, a report, or a certificate, where format_option can be one of the following (case insensitive):
        cert <private_key> <public_key>: a remote attestation certificate in DER format.
        LEGACY_REPORT_REMOTE: a report in OE_FORMAT_UUID_LEGACY_REPORT_REMOTE format.
        SGX_ECDSA: evidence in OE_FORMAT_UUID_SGX_ECDSA format.
        SGX_EPID_LINKABLE: evidence in OE_FORMAT_UUID_SGX_EPID_LINKABLE format.
        SGX_EPID_UNLINKABLE: evidence in OE_FORMAT_UUID_SGX_EPID_UNLINKABLE format.
    -p, --quote-proc <in|out>: use SGX in-process or out-of-process quoting.
    -o, --out <filename>: generate an output file for a remote attestation certificate, a report, or evidence.
    -e, --endorsements <filename>: output a report or evidence, and also its endorsements binary.
    -v, --verify: verify the generated remote attestation certificate, report, or evidence.
    -l, --log <filename>: generate a log file (default: oeutil_generate_evidence.log).
    --verbose: enable verbose output.

Note that parameters are not case-sensitive.

Example 1. Generate, verify and dump a ceritificate. Without "--out", there will be no certificate output file:

    ./oeutil generate-evidence --format cert keyecec.pem publickeyec.pem --verify --verbose

Example 2. Generate an OE report and output its endorsements binary to "endorsements.bin", and output OE report to "report.bin":

    ./oeutil generate --format legacy_report_remote --endorsements endorsements.bin --out report.bin

Example 3. Generate and verify OE evidence in SGX_ECDSA format, dump evidence buffer and its verified claims, and output OE evidence to "evidence.bin":

    ./oeutil gen --format sgx_ecdsa --verify --verbose --out evidence.bin

-----

## Using OpenSSL to create a key pair

A user can use OpenSSL to create an RSA key pair or an EC key pair. Then, the public key can be used in a certificate.

### Generate a key pair

A user can generate an RSA private key of size 2048, and output it to a file named `key.pem` with the following command:

    openssl genrsa -out keyrsa.pem 2048

A user can also generate an EC private key of size 256:

    openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem

### Extract a key pair

A user can extract the public RSA key from the generated RSA key pair, and use it in a certificate:

    openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem

A user can also extract the public EC key from the generate EC key pair:

    openssl ec -in keyec.pem -pubout -out publicec.pem
