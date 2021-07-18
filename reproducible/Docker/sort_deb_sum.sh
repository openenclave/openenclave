#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# sort_deb_sum.sh extracts, sorts and replaces the mdsums file in a deb package which is generated in 
# a random order. This allows a reproducible deb package.

printerr()
{
   echo $1 >&2
}

printusage()
{
   echo "usage: $0 <deb file path>">&2
   echo "     <deb file path> : path of deb file to be fixed>">&2
}

if [ "$#" -ne 1 ]
then
    printusage 
    exit -1
fi

DEB_PATH=$1
tmp_dir=$(mktemp -d )

if cp ${DEB_PATH} $tmp_dir
then
   echo "----- copied ${deb_file_name}" 
else
   printerr "ERROR: could not find ${DEB_PATH}"
   exit 1
fi

pushd ${tmp_dir}

# we bring the deb into a temp directory.
# then we split the deb into its components, control.tar.gz and data.tar.gz.

deb_file_name=$(basename ${DEB_PATH})
if ar x ${deb_file_name}
then
   echo "----- found ${deb_file_name}" 
else
   printerr "ERROR: could not find ${deb_file_name}"
   exit 2
fi

# then we make another temp dir and extract control.tar.gz contents, control and md5sums
mkdir -p ./control_files
pushd control_files
if tar xvfz ../control.tar.gz
then
   echo "----- extract control tar" 
else
   printerr "ERROR: could not extract control.tar.gz"
   exit 2
fi

# Then sort md5sums. It is in a random order and that ruins reproducibility
# This is slightly more specialised because we must preserve the original timestamp
# tar file entries have a user/group/timestamp block and if that changes the sha256sum 
# is altered.
sort md5sums >t
touch -r md5sums t  # applies md5sums timestamp to t
mv t md5sums

# now put together in reverse order
if tar cvfz ../control.tar.gz control md5sums
then
   echo "----- re-tar control tar" 
else
   printerr "ERROR: could not re-tar control.tar.gz"
   exit 2
fi
popd

if ar r ${deb_file_name}.sorted debian-binary control.tar.gz data.tar.gz
then
   echo "---- re-archive ${deb_file_name}" 
else
   printerr "ERROR: could not re-archive ${deb_file_name}"
   exit 3
fi
popd 

# copy back to the original location with a modified name. 
# We leave it to the caller to rename the file
if cp ${tmp_dir}/${deb_file_name}.sorted $(dirname ${DEB_PATH})
then
   echo "---- copy ${tmp_dir}/${deb_file_name}.sorted to $(dirname ${DEB_PATH}) " 

else
   printerr "ERROR: could not copy ${tmp_dir}/${deb_file_name}.sorted to $(dirname ${DEB_PATH})" 
   exit 4
fi
# clean up after ourselves
rm -rf ${tmp_dir}
