#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Set lock file depending on Windows or Linux OS
if [[ "${OSTYPE}" == "msys" || "${OSTYPE}" == "cygwin" ]]; then
    lock="${SYSTEMROOT}\Temp\threadpool"
else
    lock="/var/tmp/threadpool"
fi
destfile="$1"
pubkey_file="$2"

#Check if the lock exists
if [ -f "$lock" ]; then
    echo "threadpool_enc_pubkey.h is being written"
    exit 1
fi

# Create the lock
touch "$lock"
cat > "$destfile" << EOF
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef THREADPOOL_PUBKEY_H
#define THREADPOOL_PUBKEY_H

EOF

printf 'static const char THREADPOOL_ENC_PUBLIC_KEY[] =' >> "$destfile"
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
