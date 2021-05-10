oecert
=====

`oecert` is a debugging utility that generates the following files in binary format, or dump them in readable text, and verify them:

 1. Self-signed certificates (in der format) used for remote attestation over TLS.
 2. An OE report.
 3. An OE evidence.
 4. An endorsement for OE report/evidence.

For certificates, the user can pass in the public/private key.
`oecert` is not suitable for production use.

Usage: `oecert Options`

where `Options` are:

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
    -l, --log <filename>: generate a log file (default: oecert.log).
    --verbose: enable verbose output.

Note that parameters are not case-sensitive.

Example 1 Generate, verify and dump a ceritificate. Without "--out", there will be no certificate output file:

    ./oecert --format cert keyecec.pem publickeyec.pem --verify --verbose

Example 2 Generate an OE report and output its endorsements binary to "endorsements.bin", and output OE report to "report.bin":

    ./oecert --format legacy_report_remote --endorsements endorsements.bin --out report.bin

Example 3 Generate and verify OE evidence in SGX_ECDSA format, dump evidence buffer and its verified claims, and output OE evidence to "evidence.bin":

    ./oecert --format sgx_ecdsa --verify --verbose --out evidence.bin


Creating RSA and EC keys pairs in linux using openssl.
Generate an RSA private key, of size 2048, and output it to a file named key.pem
=====
openssl genrsa -out keyrsa.pem 2048


Extract the public key from the key pair, which can be used in a certificate:
=====
openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem


Generate an EC private key, of size 256, and output it to a file named key.pem
=====
openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem


Extract the public key from the key pair, which can be used in a certificate
=====
openssl ec -in keyec.pem -pubout -out publicec.pem
