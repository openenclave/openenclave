#!/usr/bin/env bash

function write_pubkey()
{
    local varname="$1"
    local infile="$2"
    local outfile="$3"

    printf 'static const char %s[] =' "$varname" >> "$outfile"
    while IFS="" read -r p || [ -n "$p" ]
    do
        printf '\n    \"%s\\n\"' "$p" >> "$outfile"
    done < "$infile"

    printf ';\n' >> "$outfile"
}

destfile="$1"
enclave1_file="$2"
enclave2_file="$3"

cat > $destfile << EOF
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_REMOTE_ATTESTATION_H
#define SAMPLES_REMOTE_ATTESTATION_H

EOF

write_pubkey ENCLAVE1_PUBLIC_KEY $enclave1_file $destfile
printf "\n" >> $destfile
write_pubkey ENCLAVE2_PUBLIC_KEY $enclave2_file $destfile

cat >> $destfile << EOF

#endif /* SAMPLES_REMOTE_ATTESTATION_H */
EOF
