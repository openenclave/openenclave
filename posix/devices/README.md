devices:
========

This directory contains device implementations, such as file systems and
socket layers. These devices are managed by [**liboeposix**](..), which
routes each client request to a target device.

Each device is packaged as a static library. To use a device, the enclave
application links the library and loads it by calling a load function. This
directory builds the following libraries, shown with their associated load
functions.

- **liboehostfs** - oe_load_module_hostfs()
- **liboesgxfs** - oe_load_module_sgxfs()
- **liboehostsock** - oe_load_module_hostsock()
- **liboehostresolver** - oe_load_module_hostresolver()
- **liboehostepoll** - oe_load_module_hostepoll()
- **liboeeventfd** - oe_load_module_eventfd()
