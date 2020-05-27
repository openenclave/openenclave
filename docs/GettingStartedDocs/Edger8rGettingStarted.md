# Getting started with the Open Enclave edger8r

Calling into and out of enclaves is done through special methods that switch into and out of the enclave, along with the marshaling of parameters that are passed into these functions.
A lot of the code necessary to handle these calls and parameter marshaling are common to all function calls.
Marshaling parameters from the host to the enclave for security purposed, and in doing so also helps to mitigate certain processor vulnerabilities (like spectre).
The Open Enclave edger8r helps to define these special functions through the use of `edl` files and then generates boilerplate code for you.

This document explains the following concepts:

- Define secure functions in the `edl` that an unsecure application host can call into.
- Define unsecure functions in the `edl` that a secure enclave can call into.
- Generate the marshaling code and header files from the `edl` file using the `oeedger8r` tool.
- Define method parameters in the `edl` file and talks about various things to consider while deciding how to pass parameters

It is important to make a note about what memory can be accessed from where, and how this may be different between different architectures. On Intel SGX the enclave can directly access unsecure memory allocated in the unsecure host along with the memory owned by the enclave. On ARM TrustZone on the other hand you can only access secure memory within the secure enclave. Marshaling parameters does have a performance hit, but if you want to work across platform architectures it is important to be consistent.

## The edger8r

The Open Enclave `oeedger8r` tool is based on the `edger8r` tool in Intel's SGX SDK edger8r. The format of the `edl` file is the same as that defined in their SDK. Our `oeedger8r` tool uses Intel's `edl` file parser and our tool then outputs files based on our own open enclave SDK functions and parameter marshaling code. `edl` stands for Enclave Definition Language. The full Intel `edl` syntax is defined on the [Intel SDX EDL syntax reference](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax).
Note, however, that Open Enclave does not support the full syntax that Intel defines and will emit an error if an unsupported feature is used. Items not currently supported include:

- `private` specified on methods is not allowed, only `public`.
- switchless calls from host to enclave, and enclave to host are not supported.
- Calling conventions (like cdecl, stdcall, fastcall) for enclave functions called from host are not supported.
- Reentrant calls are not supported and the allow list is ignored, emitting a warning.
- wchar_t parameters emit a warning because the sizes vary between platforms which could cause problems if the data is sent from one machine to another.

## Some basics

In much the same way you write function prototypes for shared libraries functions in header files in C/C++, `edl` files are used to define secure and unsecure functions that the edger8r tool can then use to generate these function prototype header,  the code to switch between the secure and unsecure environment, and the code to marshal the function properties.

The basic format of these `edl` files are as follows:

```edl
enclave {
    trusted {
        public return_type enclave_method_1(
            [parameter_constraints] parameter_type parameter_name
            );
        public return_type enclave_method_2(
            [parameter_constraints] parameter_type parameter_name
            );
    };

    untrusted {
        return_type host_method_1(
            [parameter_constraints] parameter_type parameter_name
            );
        return_type host_method_2(
            [parameter_constraints] parameter_type parameter_name
            );
    };
};
```

*return_type* is a C data type defining the type of the return value.

*enclave_method_** are the methods that are exposed from the secure enclave to the unsecure host. The unsecure host will call these methods and the enclave will implement them.

*parameter_constraints* are a set of directives that describe such things as if a parameter is a pointer, if the parameter is for passing in data or returning data, along with other restraints like the length of memory buffers.

*parameter_type/parameter_name* are a set of statements defining a parameter name and the associated parameter type.

*host_method_** are methods that are exposed from the unsecure host to the secure enclave. The enclave will call these methods and the host will implement them.

A simple example of an enclave method and host method are as follows, lets call this file `hello.edl`:

```edl
enclave {
    trusted {
        public oe_result_t enclave_hello(
            [user_check] char *this_is_a_string
            );
    };

    untrusted {
        oe_result_t host_hello(
            [user_check] char *this_is_a_string
            );
    };
};
```

Once the `edl` methods are defined the headers and marshaling code needs to be generated using the open enclave SDK tool `oeedger8r`.

A single command can be issued to generate both the secure and unsecure files, or they can be generated separately.

As an example, on Linux, for an application targeting SGX, to generate both secure and insecure headers and marshaling files, run the following (assuming that the Open Enclave SDK package was installed to /opt/openenclave):

```bash
oeedger8r --trusted-dir enclave-directory --untrusted-dir host-directory hello.edl --search-path /opt/openenclave/include --search-path  /opt/openenclave/include/openenclave/edl/sgx
```

On Windows, for an application targeting SGX, to generate both secure and insecure headers and marshaling files, run the following (assuming that the Open Enclave SDK package was installed to c:\openenclave):

```cmd
oeedger8r.exe  --trusted-dir enclave-directory --untrusted-dir host-directory hello.edl --search-path c:\openenclave\include --search-path c:\openenclave\include\openenclave\edl\sgx
```

To generate just the secure code for the enclave in the current directory run the following:

On Linux:

```bash
oeedger8r --trusted hello.edl --search-path /opt/openenclave/include --search-path  /opt/openenclave/include/openenclave/edl/sgx
```

On Windows:

```cmd
oeedger8r --trusted hello.edl --search-path c:\openenclave\include --search-path c:\openenclave\include\openenclave\edl\sgx
```

To generate just the unsecure code for the host in the current directory run the following:

On Linux:

```bash
oeedger8r --untrusted hello.edl --search-path /opt/openenclave/include --search-path  /opt/openenclave/include/openenclave/edl/sgx
```

On Windows:

```cmd
oeedger8r --untrusted hello.edl --search-path c:\openenclave\include --search-path c:\openenclave\include\openenclave\edl\sgx
```

The generator creates the following trusted file:

- hello_t.h defining host functions that can be called from the enclave
- hello_t.c which has the marshaling code for functions that are calling out of the enclave to the unsecure host, as well as unmarshaling code for the functions the enclave implement that are called from the unsecure host.

The generator creates the following untrusted files:

- hello_u.h defining the enclave functions that can be called from the unsecure host
- hello_u.c which has the marshaling code for functions that are calling out of the unsecure host to the secure enclave, as well as unmarshaling code for the functions the unsecure host implement that are called from the secure enclave.

In this example the enclave will implement a method called `enclave_hello()` similar to this:

```c
#include "hello_t.h"

oe_result_t enclave_hello(
    char* this_is_a_string
    )
{
    oe_result_t oe_return_value, method_return_value, return_value;

    // your code goes here

    // Also, lets call into host method while we are here
    oe_return_value = host_hello(&method_return_value, "this is a string");
    if (oe_return_value != OE_OK)
    {
        //This means open enclave had trouble inside the generated marshaling code itself.
        //Maybe we ran into memory problems
    }
    else
    {
        if (method_return_value != OE_OK)
        {
            //This is what our host function host_hello returned
            return_value = method_return_value;
        }
    }

    return return_value;
}
```

Note that in this code snippet we are including the `hello_t.h` header file that the `oeedger8r` tool generates. This `hello_t.h` file includes the function declarations from the host methods that we defined in the `edl` file.

The unsecure host method `host_hello()` would be similar as follows:

```c
#include <openenclave.h>
#include "hello_u.h"

oe_result_t host_hello(
    char* this_is_a_string
    )
{
    // code goes here

    return OE_OK;
}
```

In this case we include the `hello_u.h` header file instead of `hello_t.h` because we want the functions we can call from the unsecure host to be defined. In this case it defines the `enclave_hello()` method.

Lets now include the hosts `main()` function that calls into the enclave:

```c
#include <openenclave/host.h>
#include "hello_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_result_t method_return;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        // pass the enclave shared library as the first parameter
        goto exit;
    }

    // Create the enclave
    result = oe_create_hello_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, 0, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        // Failed to create enclave
        goto exit;
    }

    // Call into the enclave
    result = enclave_hello(enclave, &method_return, "this is a string");
    if (result != OE_OK)
    {
        // calling into enclave itself failed
        goto exit;
    }
    if (method_return != OE_OK)
    {
        // method itself returned a failure
        goto exit;
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
```

## More complicated stuff!

So we did a simple sample above which had some return codes and took a simple string. In reality this may be useful but does not cover more complex scenarios. So now we will start doing some more complex stuff.

### Basic C types

Most of the standard types are available for use. Lets generate a function that takes one of each:

```edl
enclave  {
    trusted {
        public void enclave_basic_types(
            char arg1,
            short arg2,
            int arg3,
            float arg4,
            double arg5,
            long arg6,
            size_t arg7,
            unsigned arg8,
            int8_t arg9,
            int16_t arg10,
            int32_t arg11,
            int64_t arg12,
            uint8_t arg13,
            uint16_t arg14,
            uint32_t arg15,
            uint64_t arg16,
            wchar_t arg17
        );
    };
};
```

Note that `wchar_t` parameters are different sizes on Windows and Linux platforms, namely on Windows they are 2 bytes and on Linux by default they are 4 bytes. If you use this type the `oeedger8r` will emit a warning. This is not a problem if you are just keeping the data on the local platform, but if you are planning on packaging up a `wchar_t` data type and forwarding it to another platform you may run into unexpected problems due to the size differences.

In the above example enclave_basic_types passes one of each basic type as a parameter. Nothing too complicated here. Note that these types can also be the return type.

### Pointers

Adding pointers to parameters gets interesting. Consider this next example:

```edl
enclave  {
    trusted {
        public void enclave_pointer_types(
            uint32_t* arg1
        );
    };
};
```

So in C/C++ if something is a pointer it allows us to pass in a pointer to a `uint32_t` value, but it also gives us the opportunity to pass back a value to the caller. We have not decorated this argument so which is it? The marshaling code needs to know this such that it can marshal parameters into the enclave and marshal the data back out again in the case of it being bidirectional.

Lets get specific:

```edl
enclave  {
    trusted {
        public void enclave_pointer_types(
            [in] uint32_t* arg1
        );
    };
};
```

OK, so now we know it is a pointer to a `uint32_t` value and we only need to marshal it into the enclave.

Alternatively we can say this is an outbound parameter only:

```edl
enclave  {
    trusted {
        public void enclave_pointer_types(
            [out] uint32_t* arg1
        );
    };
}
```

Now the marshaling code will gather the final value of the pointer in the enclave function and return it back to the caller.

Maybe we have an existing variable that is a count and the function needs to increment the value in the variable, then we would need it to be bidirectional as follows:

```edl
enclave  {
    trusted {
        public void enclave_pointer_types(
            [in, out] uint32_t* arg1
        );
    };
};
```

The marshaling of parameters into the enclave will allocate memory in the enclave and, if it is an `in` parameter, will copy your version of the data into it. This means that if you call into multiple enclave functions at the same time, as in from multiple threads, with the same pointer you are going to get confusing results and the last function to return will probably win by copying its own private copy back to the host,

Pointer marshaling  is assuming you are only pointing to a single item and not an array. If you want a pointer to a buffer bigger, read on!

### Arrays

We just mentioned in the previous section that by default a pointer is equivalent of an array of size one, so what if we want to pass in a fixed size array. We would have something like the following:

```edl
enclave  {
    trusted {
        public void enclave_array_method(
            [in, out] uint32_t arg1[10]
        );
    };
};
```

Here we have a bidirectional array of size 10. The marshaling code will create a buffer in the enclave of size 10 elements and marshal in whatever was passed by the host. Once the function is complete it copies out the memory back to your memory buffer that was passed in as the parameter.

We can also do multi-dimensional arrays:

```edl
enclave  {
    trusted {
        public void enclave_array_method(
            [in] uint32_t arg1[10][4]
        );
    };
};
```

In this example we have a 10x4 array that is passed in to the enclave function, but we do not marshal back the array if things change within the enclave.

### Variable length buffers

Fixed arrays have their place. They certainly make life easy when trying to get buffers back from the enclave. But we may need to get a little more complicated. Imagine this example:

```edl
enclave  {
    trusted {
        public void enclave_pointer_method(
            [out, count=total_length] uint32_t *buffer,
            size_t total_length,
            [out] size_t* amount_used
        );
    };
};
```

This example is useful because we may allocate a buffer to hold 1024 `uint32_t` in the host, but the function may only use 20 slots.

Interesting thing to note about this definition is the `count` item in the `buffer` parameter. This tells how many elements are in the buffer. This can be a constant number itself or a parameter like `total_length` in this example.  Then we return the amount of the buffer the enclave used, `amount_used` in the example.

`count` is useful for specifying the number of elements, but sometimes you may want to specify the length in bytes instead, in which case use `size` instead of `count`.

### Strings are special

If a function passes in a `char *` you would think it is a string, but by default all pointers are defaulted to a length of one item. Strings are null terminated which is nice, but do we really need to specify a length as well? The answer is it depends. For performance reasons it is better to pass in the size of a buffer so we do not need to work it out ourselves, but we can define a string parameter as follows:

```edl
enclave  {
    trusted {
        public void enclave_pointer_types(
            [string, in] char *string_ptr
        );
    };
};
```

In this case it knows it is a null terminated string as a result of the `[string]` specifier so the marshaling code can calculate the length on your behalf.

`[string, out]` is not supported in `edl`. On top of that `[sting, in, out]` is not encouraged because it is confusing and is equivalent of having a fixed length buffer the size of the initial `in` buffer so it cannot be grown in length.

So how do we deal with sending a variable length string back to the caller? We will be handling returning variable length buffers in a later section with the `[user_check]` definition.

!!! TODO !!! Can you return string ? What does it mean to return a `char*`? Is it an array of sized 1? Can you decorate it as `[string]`? Or can you decorate it with a length of `[count=10]`?

### Structures

You may want to pass in or out arbitrary structures to your function. These work in a similar way to your basic types and pointer types, and even arrays and variable length arrays. The only difference is the type itself.

Take this example:

```edl
enclave  {
    struct MyStruct0 {
        int x;
    };

    struct MyStruct1 {
        MyStruct0 s0;
        int y;
    };

    trusted {
        public void enclave_pointer_types(
            [in] MyStruct1 struct_param
        );
    };
};
```

In this case we have defined the structure using simple types and passed the structure by value as a parameter. We can define it as a pointer in the same way, maybe as an out parameter this time:

```edl
enclave  {
    struct MyStruct0 {
        int x;
    };

    struct MyStruct1 {
        MyStruct0 s0;
        int y;
    };

    trusted {
        public void enclave_pointer_types(
            [out] MyStruct1* struct_param
        );
    };
};
```

Unfortunately we cannot get much more complicated with structures than this. For instance define the following structures within `edl` because of the pointer is not recommended:

```c
struct MyStruct0 {
    int x;
};

struct MyStruct1 {
    MyStruct0* s0;
    int y;
};
```

In this structure declaration member variable `s0` is a pointer and the marshaling code cannot handle this pointer properly. This would be especially the case if you wanted `MyStruct0` to be allocated in the enclave and marshaled back automatically to host memory. In this case if you point enclave memory and marshal this structure back to the host, the host will to be able to read the contents of the memory. The enclave could allocate memory from the host and then that pointer will be marshaled and the host can then access that.

You can have arrays of structures though, and you can specify the sizes as constant declarations or as a parameter as defined in the variable length buffer section.

### Enumerations

Currently you cannot do a `#define` in the `edl`, but you can create enumerations.

An example of a method using enumerations is as follows:

```edl
enclave  {
    enum Color {
        Red = 1,
        Green = 2,
        Blue = 80000
    };

    trusted {
        public Color enclave_pointer_types(
            Color in_param,
            [out] Color* out_param
        );
    };
};
```

The `Color` enumeration can be used as a return, or as in and out parameters.

Enumerations *cannot* be used as array sizes though, so you cannot do the following:

```edl
enclave  {
    enum Sizes {
        ArraySize = 10
    };

    trusted {
        public Color enclave_pointer_types(
            [in] char in_param[ArraySize]
        );
    };
};
```

### Foreign types

Types that are defined in external include files can be used within `edl`.

Lets define something in a header file `my_type.h` for inclusion:

```c
typedef struct
{
    int x;
    int y;
} my_type_t;

typedef my_type_t* my_type_ptr_t;
```

Now we can define our `edl` file as follows:

```edl
enclave  {
    include "my_type.h"

    trusted {

        public void call_one(
            [in] my_type_t* in_param
            );

        public void call_two(
            [in, isptr] my_type_ptr_t in_param
            );
    };
};
```

In this case both function `call_one` and `call_two` pass a pointer to `my_type_t`. In the first case the pointer is explicit, but in the second case the type `my_type_ptr_t` hides the fact that it is pointer in the `edl` definition because the parser does not actually parse what is in `my_type.h`. As a result of the parameter for `call_two` not knowing `in_param` is a pointer we add the `isptr` qualifier to the parameter.

`isptr` parameter marshaling is handled in the same way as `struct` parameters. Directional attributes can be added for in and out. If the parameter type has any pointers embedded the pointers will be marshaled as is and what they point to are not marshaled into host memory.

### You are on your own

OK, so sometimes you need to do other things that just do not seem to be supported, or function in unexpected ways. Imagine the following example:

```edl
enclave  {
    trusted {

        public void call_one(
            [out] char** out_string
            );
    };
};
```

The above example will not marshal the actual string back from the enclave to the untrusted host, all it will do is marshal the pointer back. If in the enclave you have code similar to this:

```c
&out_string = "this is a string"
```

your host will not have access to the string itself. To pass a string back to the untrusted host the enclave will need to allocate memory out of the host and copy the string into that. Even this approach will only work on some platforms like ARM TrustZone.

To make things more explicit in your definition `user_check` should be used like this:

```edl
enclave  {
    trusted {

        public void call_one(
            [user_check] char** out_string
            );
    };
};
```

So what does `user_check` mean? Well it kind of means you are on your own and you need to manage the memory yourself. Within the enclave function `call_one` you will need to allocate memory from the host and copy the string into that memory. Then back in the host you will get the string back and will need to delete it after use.

This is what the code in the enclave could look like:

```c
void call_one(char** out_string)
{
    *out_string = oe_host_strndup("Hello world", 12);
}
```

Here the enclave is calling the open enclave host implementation of `strndup` so the host is able to see the memory.

Within the host we would do the following:

```c
void main(void)
{
    //enclave initialization goes here

    oe_result_t result;
    char* out_string = NULL;
    result = call_one(enclave, &out_string);
    if (result == OE_OK)
    {
        // We now have a string in out_string

        // When we are done we need to free it
        free(out_string);
    }
}
```

Another common usage that requires `user_check` is `void*`. This has one more level of complexity because `edl` does not like you even specifying it as they want you to strongly type things. Forcing strong types is often not possible, so we work around it. In this case we need to define our own type and tell `edl` it is a `user_check` so it does not try to marshal it.

In this case we need to define a new type `void_ptr` in our own header, lets call it `types.h`:

```c
typedef void* void_ptr;
```

Now we can define our `edl` as follows:

```edl
enclave {
    include "types.h"

    trusted {
        public void call_with_void_ptr(
            [user_check, isptr] void_ptr in_ptr,
            [user_check] void_ptr* out_ptr);
    };
};
```

The enclave function would now look like this:

```c
#include "edl_t.h"

void call_with_void_ptr(
    void_ptr in_ptr,
    void_ptr* out_ptr
)
{
    // Code goes here
}
```

The downside of `[user_check]` is not all platforms will support this. Because Intel SGX can access host memory from the enclave this will work, but with ARM TrustZone the enclave can only access memory in the enclave and not the host. If you want more cross platform you will need to avoid `[user_check]`.

Overall, pointers to pointers should be avoided.
If an out parameter has a maximum size you can pass an `[in, out]` parameter with an array of the maximum length and have an out parameter to define the amount used on return.
Another option is for the enclave to call back into the host with the results of the call. An example would be as follows:

```edl
enclave {
    include "types.h"

    trusted {
        public void call_one();
    };

    untrusted {
        void host_accept_call_one_output ([in] char* string);
    }
};
```

In this case the string parameter in the call back to the host can be as long as is needed.
