#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if ! command -v nc &> /dev/null
then
   echo "netcat program not found. Skipping test."
   exit 0
fi

host/event_host enc/event_enc --once &
for itr in {1..10}
do
    sleep 0.5 && echo Hi | nc 0.0.0.0 12344 && exit 0
    echo "iteration : $itr"
done
exit 1

