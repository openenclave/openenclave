Install
=======

You can locally install the SDK from the compiled Open Enclave tree by specifying the install-prefix to the cmake call before calling "make install". As of now, there is no real need to install the SDK system-wide, so you might use a tree in your home directory:
```
build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=~/openenclave ..
build$ make install
```
Note: Optional installation detailed information could be found [here](AdvancedInstallInfo.md)
