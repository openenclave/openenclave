#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

destfile="$1"
input_file="$2"

# Store text in variables and then write file all at once at the end. This
# will keep build tools from consuming an incomplete header file.

SECTION1="$(cat <<-EOF
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H
#define SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H

static const unsigned char SERVER_ENCLAVE_MRENCLAVE[] =
{
EOF
)"

SECTION2=""
while read -r line; do
  if [[ $line == mrenclave=* ]]; then
    read -r mrenclave < <(echo "$line" | cut -d'=' --fields=2)
    if [[ "${mrenclave: -1}" = $'\r' ]]; then
      mrenclave="${mrenclave:0: -1}"
    fi

    for (( i=0; i<${#mrenclave}; i=i+2)); do
      echo -n "" >> "$destfile"
      SECTION2=$SECTION2"0x${mrenclave:$i:2}"
      index=$((${#mrenclave} - 2))
      if [ $i -lt $index ]; then
        SECTION2=$SECTION2",\n"
      fi
    done
  fi
done < "$input_file"


SECTION3="$(cat <<-EOF
};

#endif /* SAMPLES_ATTESTED_TLS_SERVER_UNIQUE_ID_H */
EOF
)"

echo -ne "$SECTION1$SECTION2$SECTION3" > "$destfile"

