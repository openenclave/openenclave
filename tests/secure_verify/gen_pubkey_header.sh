#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

lock="/var/tmp/oecert_lock"
destfile="$1"
pubkey_file="$2"

#Check if the lock exists
if [ -f "$lock" ]; then
    echo "secure_verify_enc_pubkey.h is being written"
    exit 1
fi

# Create the lock
touch "$lock"
cat > "$destfile" << EOF
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef secure_verify_PUBKEY_H
#define secure_verify_PUBKEY_H

EOF

printf 'static const char SECURE_VERIFY_ENC_PUBLIC_KEY[] =' >> "$destfile"
while IFS="" read -r p || [ -n "$p" ]
do
    # Sometimes openssl can insert carriage returns into the PEM files. Let's remove those!
    CR=$(printf "\r")
    p=$(echo "$p" | tr -d "$CR")
    printf '\n    \"%s\\n\"' "$p" >> "$destfile"
done < "$pubkey_file"
printf ';\n' >> "$destfile"

cat >> "$destfile" << EOF

#endif /* OECERT_ENC_PUBLIC_KEY */
EOF

# Remove the lock
rm "$lock"
