#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Set lock file depending on Windows or Linux OS
if [[ "${OSTYPE}" == "msys" || "${OSTYPE}" == "cygwin" ]]; then
    lock="${SYSTEMROOT}\Temp\oeutil_lock"
else
    lock="/var/tmp/oeutil_lock"
fi
destfile="$1"
pubkey_file="$2"

# Check if the lock exists
if [ -f "$lock" ]; then
    echo "oeutil_enc_pubkey.h is being written"
    exit 1
fi

# Create the lock
touch "$lock"
cat > "$destfile" << EOF
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OEUTIL_PUBKEY_H
#define OEUTIL_PUBKEY_H

EOF

printf 'static const char OEUTIL_ENC_PUBLIC_KEY[] =' >> "$destfile"
while IFS="" read -r p || [ -n "$p" ]
do
    # Sometimes openssl can insert carriage returns into the PEM files. Let's remove those!
    CR=$(printf "\r")
    p=$(echo "$p" | tr -d "$CR")
    printf '\n    \"%s\\n\"' "$p" >> "$destfile"
done < "$pubkey_file"
printf ';\n' >> "$destfile"

cat >> "$destfile" << EOF

#endif /* OEUTIL_ENC_PUBLIC_KEY */
EOF

# Remove the lock
rm "$lock"
