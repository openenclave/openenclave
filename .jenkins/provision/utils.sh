#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


function retrycmd_if_failure() {
    set +o errexit
    retries=$1; wait_sleep=$2; timeout=$3; shift && shift && shift
    for i in $(seq 1 "$retries"); do
        if timeout "$timeout" "${@}"; then
            break
        fi
        if [[ $i -eq $retries ]]; then
            echo "Error: Failed to execute '$*' after $i attempts"
            set -o errexit
            return 1
        fi
        sleep "$wait_sleep"
    done
    echo "Executed '$*' $i times"
    set -o errexit
}
