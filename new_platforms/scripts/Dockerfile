FROM ubuntu

WORKDIR /app

COPY socketclient_host ./
COPY libteec.so /lib/
COPY aac3129e-c244-4e09-9e61-d4efcf31bca3.ta ./

CMD echo "$(date --utc +"[%Y-%m-%d %H:%M:%S %:z]"): Starting Module" && \
    cp aac3129e-c244-4e09-9e61-d4efcf31bca3.ta /lib/optee_armtz/ && \
    ./socketclient_host $HOST $PORT
