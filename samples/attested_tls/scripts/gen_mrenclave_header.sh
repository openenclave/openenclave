#!/usr/bin/env bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

destfile="$1"
input_file="$2"

cat > "$destfile" << EOF
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H
#define SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H

EOF

printf 'static const unsigned char SERVER_ENCLAVE_MRENCLAVE[] =' >> "$destfile"
printf '\n{' >> "$destfile"

while read -r line; do
  if [[ $line == mrenclave=* ]]; then
    read -r mrenclave < <(echo "$line" | cut -d'=' --fields=2)
    for (( i=0; i<${#mrenclave}; i=i+2)); do
      echo "0x${mrenclave:$i:2}" >> "$destfile"
      index=$((${#mrenclave} - 2))
      if [ $i -lt $index ]; then
        printf "," >> "$destfile"
      fi
    done
  fi
done < "$input_file"

printf '};\n' >> "$destfile"

cat >> "$destfile" << EOF

#endif /* SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H */
EOF

