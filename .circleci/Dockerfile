# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Create the docker image on a Linux VM from the .circleci directory
# using the following command: (docker should be installed on this VM)
# x is the version number being created
# sudo docker build --no-cache=true -t oetools:1.x .

# Use the following commands to view the image before and after tagging it,
# tag the image and push the image to docker hub
# docker image ls
# docker login
# docker tag oetools:1.x oeciteam/oetools:1.x
# docker image ls
# docker push oeciteam/oetools:1.x


FROM ubuntu:16.04

ENV PATH="/cmake-3.11.4-Linux-x86_64/bin:${PATH}"

RUN apt-get -y update
RUN apt-get -y install sudo git

# install all the packages specified in install-prereqs except cmake
RUN apt-get -y install clang-format gcc g++ make gdb autoconf libtool doxygen graphviz gawk libexpat1-dev openssl libssl-dev subversion

# install wget as this is needed for SGX1FLC builds and for getting latest cmake
RUN apt-get -y install wget

# since cmake is not latest in apt-get repository,so we install it separately
RUN sudo wget https://cmake.org/files/v3.11/cmake-3.11.4-Linux-x86_64.tar.gz
RUN tar xf cmake-3.11.4-Linux-x86_64.tar.gz

