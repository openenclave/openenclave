# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#
# IMPORTANT- Please update the version number in the next sentence
# when you create a new docker image.
#
# This Dockerfile script builds an image for tag oetools-azure:1.9

# To use this Dockerfile, you will need to install docker-ce.
# Instructions for installing it on Ubuntu 16.04 LTS are at:
# https://docs.docker.com/install/linux/docker-ce/ubuntu/
#
# Once installed, build a docker image from .jenkins folder and
# it will use this Dockerfile by default:
#     openenclave$ sudo docker build --no-cache=true -t oetools-azure:<version> -f .jenkins/Dockerfile .
#
# For example, for version 1.x:
#     openenclave$ sudo docker build --no-cache=true -t oetools-azure:1.x -f .jenkins/Dockerfile .
#
# Note that DNS forwarding in a VM can interfere with Docker
# getting updates from Ubuntu apt-get repositories as part of the
# Dockerfile script. To work around this, try disabling dnsmasq:
#     $ sudo nano /etc/NetworkManager/NetworkManager.conf
#     $ sudo service network-manager restart
#     $ sudo service docker restart
#
# To view the image after it is created or tagged:
#     $ sudo docker image ls
#
# Jenkins pulls the images it uses from the private oejenkinscidockerregistry
# repository on Azure. To upload the image to that repository:
#     $ sudo docker login oejenkinscidockerregistry.azurecr.io
#     $ sudo docker tag oetools-azure:<version> oejenkinscidockerregistry.azurecr.io/oetools-azure:<version>
#     $ sudo docker push oejenkinscidockerregistry.azurecr.io/oetools-azure:<version>
#     $ sudo docker logout
#
# You can check that the image has been successfully uploaded by checking
# the oejenkinscidockerregistry Container registry in Azure at this link,
# assuming you have proper permissions:
# https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/e5839dfd-61f0-4b2f-b06f-de7fc47b5998/resourceGroups/OE-Jenkins-CI/providers/Microsoft.ContainerRegistry/registries/oejenkinscidockerregistry/overview

FROM ubuntu:16.04

ADD scripts/ansible /ansible

RUN /ansible/install-ansible.sh && \
    ansible localhost --playbook-dir=/ansible -m import_role -a "name=linux/docker tasks_from=ci-setup.yml" -vvv && \
    /ansible/remove-ansible.sh && \
    rm -rf /ansible && \
    # Configure Git in target image to enable merge/rebase actions.
    git config --global user.email "oeciteam@microsoft.com" && \
    git config --global user.name "OE CI Team"
