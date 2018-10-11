# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: 

/etc/apt/sources.list.d/msprod.list:
	echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/16.04/prod xenial main" | tee /etc/apt/sources.list.d/msprod.list
	wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
	apt-get update

clean:

install: /etc/apt/sources.list.d/msprod.list
	apt-get install -y az-dcap-client

uninstall:
	apt-get --purge remove az-dcap-client

