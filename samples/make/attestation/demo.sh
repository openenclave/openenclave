time=60
if [ ! -z "$1" ]
  then
    time="$1"
fi

gnome-terminal -e "./host/attestation_host ./enc/attestation_enc.signed.so -port:8000 -keep-alive:$time `hostname`:8001"
gnome-terminal -e "./host/attestation_host ./enc/attestation_enc.signed.so -port:8001 -keep-alive:$time `hostname`:8000"

