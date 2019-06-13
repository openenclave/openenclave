devices:
========

This directory contains device implementations, such as file systems and
socket layers. These devices are managed by [**liboesyscall**](..), which
routes client requests to target devices.

Each device is packaged as a static library. To use a device, the enclave
application links the library and loads it by calling a load function. This
directory builds the following libraries, shown with their associated load
functions.

- **liboehostfs** - oe_load_module_hostfs()
- **liboehostsock** - oe_load_module_hostsock()
- **liboehostresolver** - oe_load_module_hostresolver()
