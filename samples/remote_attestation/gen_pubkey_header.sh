#!/usr/bin/env bash

destfile="$1"
pubkey_file="$2"

cat > "$destfile" << EOF
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_REMOTE_ATTESTATION_PUBKEY_H
#define SAMPLES_REMOTE_ATTESTATION_PUBKEY_H

EOF

printf 'static const char OTHER_ENCLAVE_PUBLIC_KEY[] =' >> "$destfile"
while IFS="" read -r p || [ -n "$p" ]
do
    printf '\n    \"%s\\n\"' "$p" >> "$destfile"
done < "$pubkey_file"
printf ';\n' >> "$destfile"

cat >> "$destfile" << EOF

#endif /* SAMPLES_REMOTE_ATTESTATION_PUBKEY_H */
EOF
