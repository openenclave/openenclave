
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# build_deb_pkg.sh  
# builds deb package, sorting the mdsums file for reproducibility

chmod -R a+w .
# Build the deb package initially
cpack -G DEB 
DPKG_RESULT=$?
if $DPKG_RESULT
then
      echo "ERROR: Cpack failed"
      exit $DPKG_RESULT
fi

pkgname=$(ls open-enclave*.deb) 
echo "Build deb package " $pkgname
/home/azureuser/sort_deb_sum.sh $pkgname 
mv $pkgname.sorted $pkgname 
cp $pkgname /output

