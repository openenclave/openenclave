# oe_log_message Callback Sample

This sample demonstrates how to customize the log function through the callback feature of oe_log_message().

## Developer Experience

By making use of the callback API of oe_log_message(), a developer can customize the output of the log message:

- The output destination can be stdout, stderr or any file. The destination is adjustable during runtime.
- The message can be adjusted according to the log level.
- The developer gets the following information- log time, enclave or host side, and log level.
Finally, the developer can define a function to customize the log message and can designate the function to process all the log messages.

## How to customize the log
To customize the log, the developer needs to prepare a customized log processing function "customized_log()":
```
void customized_log(
    void* context,
    bool is_enclave,
    const struct tm* t,
    long int usecs,
    oe_log_level_t level,
    uint64_t host_thread_id,
    const char* message)
{
    char time[25];
    strftime(time, sizeof(time), "%Y-%m-%dT%H:%M:%S%z", t);

    FILE* log_file = NULL;
    if (level >= OE_LOG_LEVEL_WARNING)
    {
        log_file = (FILE*)context;
    }
    else
    {
        log_file = stderr;
    }

    fprintf(
        log_file,
        "%s.%06ld, %s, %s, %lu, %s",
        time,
        usecs,
        (is_enclave ? "E" : "H"),
        oe_log_level_strings[level],
        host_thread_id,
        message);
}
```
which must follow the function type "*oe_log_callback_t". All these parameters are some information about logging,
but the developer has the full control to make use of them. The timestamp information, which is not printable,
should be converted to a string. Here the printing format "%Y-%m-%dT%H:%M:%S%z" is a good format that it follows the ISO 8601 rules.
After that, the printing destination is chosen, based on the log level. In principle,
it's better not to mix low priority messages with high priority messages lest important messages be flooded by tedious messages.
Finally, all the information and messages will be written to the specified destination.

To pass in the specified log file "./oe_out.txt", the file must be opened before registration.
In this case the context is used as the logging destination. Besides that, context can be casted back as any desired type, since type of context is "void*".
```
    FILE* out_file = fopen("./oe_out.txt", "w");
    oe_log_set_callback((void*)out_file, customized_log);
```
When oe_log_message() is called, the most recently registered log function will be invoked. Obviously, if it is registered before starting the enclave, all the logs are affected.
In the developer's expectation, log messages with level equal or greater than OE_LOG_LEVEL_WARNING will be written to "./oe_out.txt", and others will be written to "stderr". The typical output is as following:
```
user@host:~/samples/log_callback/build$ cat oe_out.txt
2020-09-02T09:09:21-0700.935937, H, INFO, 140309246176128, Processor supports AVX instructions [/home/user/openenclave/host/sgx/linux/xstate.c:_is_xgetbv_supported:33]
user@host:~/samples/log_callback/build$
```

## Build and run

Note that there are two different build systems supported, one using GNU Make and
`pkg-config`, the other using CMake.

### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd log_callback
mkdir build && cd build
cmake ..
make run
```

### GNU Make

```bash
cd log_callback
make build
make run
```

#### Note

The log_callback sample can run under Open Enclave simulation mode.

To run the log_callback sample in simulation mode from the command like, use the following:

```bash
# if built with cmake
./host/log_callback_host ./enclave/enclave.signed --simulate
# or, if built with GNU Make and pkg-config
make simulate
```
