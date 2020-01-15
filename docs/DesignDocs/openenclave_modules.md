# OpenEnclave Modules

The Open Enclave SDK provides a core set of functionality for build enclave
applications. Some of these features &2014; such as memory management and ecall/ocall
marshalling &2014; are required to create an enclave. Other features such as
libc functions, host filesystem, and network sockets can be optionally included
inside the enclave by the enclave developer. These optional features are known
as **Open Enclave Modules** and are static libraries that can be optionally
linked into the enclave binary.

## Currently supported modules

Currently, Open Enclave only supports modules that are part of the OE SDK source tree.
Today there are 5 optionally includable modules:

* hostfs
* libc
* hostepoll
* hostsock
* hostresolver

## Module initialization

OE modules can each have an initialization function which will be called on
first entry to the enclave. This ensures that a module are fully initialized
prior to an application using it. There are two ways to demark initialization
functions:

1. `OE_MODULE_INIT Attribute`

The `OE_MODULE_INIT` attribute can be applied to a function. This ensures that the
function is called on enclave entry.

```
OE_MODULE_INIT
void init_my_module(void)
{
    // Do stuff
}
```

2. `OE_MODULE_INIT_PRIORITY` Attribute

Optionally, modules can specify a priority for their initialization functions.
Functions with a lower priority value will be called before functions with a
higher priority value. This can be used if one module depends on another being
initialized first.

```
// mod1.c
OE_MODULE_INIT_PRIORITY(0)
void mod1_init(void)
{
    // Initialize module 1
}

// mod2.c
OE_MODULE_INIT_PRIORITY(1)
void mod2_init(void)
{
    // Do stuff that depends on mod1. This function will
    // always be called after mod1_init.
}
```

### Linker disclaimer

Because modules can be added and removed at compile-time without the core OE
library knowing about them, initialization functions are not actually
referenced by symbol. They are instead kept in their own section in the binary.
To ensure a module's initialization function is included in the final enclave
binary there are 3 options:

1. Add the module initialization function in the same file as a symbol that is
referenced in the enclave binary.

```
// mod_init.c

int always_used_symbol = 1;

OE_MODULE_INIT
void mod_init(void)
{
    // Do initialization
}

// enclave_app.c
int main_function()
{
    int val = always_used_symbol;
    // Do stuff
}
```

2. Pass a flag to tell the linker to always link the initialization function.

```
OE_MODULE_INIT
void mod_init(void)
{
    // Do initialization
}
```

Then during compilation `$CC -o enclave -lmymodule.a -W,l,-u mod_init`

3. Use a custom GNU linker script and mark the `.init_array` option as KEEP.

TODO: Link to documentation on GNU link scripts and KEEP directive.
