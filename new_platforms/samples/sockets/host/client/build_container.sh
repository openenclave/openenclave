#!/bin/bash

if [ $# -ne 4 ]; then
    echo "usage: build_container.sh <user@host> <repository> <username> <password>"
    exit 1
fi

SSH=$1
REPO=$2
USER=$3
PWD=$4

DEST=/tmp/sample
TAG=$REPO/sampleclient

ssh $SSH "mkdir $DEST; cp /lib/libteec.so $DEST/"
scp ../../../../bin/optee/samples/sockets/aac3129e-c244-4e09-9e61-d4efcf31bca3.ta $SSH:$DEST/
scp Dockerfile $SSH:$DEST/
scp sampleclientapp $SSH:$DEST/
ssh $SSH "docker build -t $TAG $DEST && docker login -u $USER -p $PWD $REPO && docker push $TAG && docker logout $REPO"
