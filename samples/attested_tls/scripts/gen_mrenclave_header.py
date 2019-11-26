# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import sys
import os

def parse_mrenclave(fname):
    enc_bytes = []
    with open(fname, "r") as f:
        for line in f:
            prefix = "mrenclave="
            if line.startswith(prefix):
                line = line[len(prefix):]
                new_byte = True
                b = ""
                for char in line:
                    if new_byte:
                        b = "0x" + char
                        new_byte = False
                    else:
                        b += char
                        enc_bytes.append(b)
                        new_byte = True

    return ("," + os.linesep).join(enc_bytes)

def gen_header(inpath, outpath):
    lines = [
        "// Copyright (c) Open Enclave SDK contributors.",
        "// Licensed under the MIT License.",
        "",
        "#ifndef SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H",
        "#define SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H",
        "",
        "static const unsigned char SERVER_ENCLAVE_MRENCLAVE[] =",
        "{"
    ]

    lines.append(parse_mrenclave(inpath))

    lines += [
        "};",
        "",
        "#endif /* SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H */",
        ""
    ]

    return os.linesep.join(lines)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: gen_mrenclave_header.py <oesign_dump> <output_file>")
        sys.exit(1)

    outpath = sys.argv[1]
    inpath = sys.argv[2]

    header = gen_header(inpath, outpath)
    with open(outpath, "w") as f:
        f.write(header)
