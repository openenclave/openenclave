# Building and Running the Samples on Linux

All the samples that come with the Open Enclave SDK installation are structured into two subdirectories (one for enclave and one for host) accordingly.

| Files/dir        |  contents                                   |
|:-----------------|---------------------------------------------|
| Makefile         | Makefile for building all samples           |
| CMakeLists.txt   | CMake file for building for all samples     |
| ./enclave        | Files needed for building the sample enclave|
| ./host           | Files needed for building the host          |

For example:

```bash
/home/yourusername:~/openenclave/share/openenclave/samples/helloworld$ ls -l
total 12
drwxr-xr-x 2 yourusername yourusername 4096 Aug 16 13:59 enclave
drwxr-xr-x 2 yourusername yourusername 4096 Aug 16 13:59 host
-rw-r--r-- 1 yourusername yourusername  245 Aug 16 13:57 Makefile
```

## Install prerequisites

Before you can build and run samples, you would need to install the prerequisites as described in the [getting started documentation](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs).

## Prepare samples

Building samples involves writing files into the working directory, which is not allowed in `/opt` unless it's running in the context of superuser (`sudo`).

Before building any of the samples, please copy them out of the `/opt/openenclave/share/openenclave/samples directory` to a directory where your current user has write permissions.

For example, assuming the Open Enclave SDK is installed to the default location `/opt/openenclave`:

```bash
cp -r /opt/openenclave/share/openenclave/samples ~/mysamples
```

## Steps to build and run samples

Each sample comes with two different build systems: one using GNU Make and pkg-config, the other using CMake. They help simplify the sample building process, which involves building and signing
binaries.

### Source the openenclaverc file

Before building any samples, you need to source the `openenclaverc` file to set up environment variables for sample building. The `openenclaverc` file can be found in the `share/openenclave` subdirectory of the package installation destination.

You can use `.` in Bash to `source`:

```bash
. <package_installation_destination>/share/openenclave/openenclaverc
```

For example, if your package_installation_destination is `/opt/openenclave`:

```bash
. /opt/openenclave/share/openenclave/openenclaverc
```

Note: You will get error messages like the following if this sourcing step was skipped.

```sh
make[2]: Entering directory '.../openenclave/samples/helloworld/enclave`
Package oeenclave-clang was not found in the pkg-config search path.
Perhaps you should add the directory containing `oeenclave-clang.pc`
```

After this you can use either GNU make or CMake to build the samples.

### Build the samples using GNU Make

The Makefile in the root of each sample directory has three rules

- build: Calls into the Makefiles in the host and enclave directories to build
- clean: Calls in to the Makefiles in the host and enclave directories to clean all generated files
- run: Runs the generated host executable, passing the signed enclave executable as a parameter
To build a sample using GNU Make, change directory to your target sample directory and run `make build` to build the sample.
Then execute "make run" to run the sample.

For example, for the helloworld sample:

```bash
~/openenclave/share/openenclave/samples$ cd helloworld/
~/openenclave/share/openenclave/samples/helloworld$ make build
~/openenclave/share/openenclave/samples/helloworld$ make run
```

### Build the samples using CMake

To build a sample using CMake, change directory to your target sample directory and execute the following commands:

```bash
mkdir build && cd build
cmake ..
make
```

Then execute "make run" to run the sample.

For example:

```bash
~/openenclave/share/openenclave/samples$ cd helloworld/
~/openenclave/share/openenclave/samples/helloworld$ mkdir build && cd build
~/openenclave/share/openenclave/samples/helloworld/build$ cmake ..
~/openenclave/share/openenclave/samples/helloworld/build$ make
~/openenclave/share/openenclave/samples/helloworld/build$ make run
```

### Running the sample in simulation mode

Some of the samples can be run in simulation mode. To run the sample in simulation mode, use `make simulate`.

### Note

More detailed information on what the samples contain, how oeedger8r is used and what files are generated during the build process can be found in the [helloworld sample README](helloworld/README.md).

For details on how to configure build and sign options, refer to [Enclave Building and Signing](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md).

### Build and Run samples with LVI mitigation

Refer to [the LVI section in the helloworld sample](helloworld/README.md#build-and-run-with-lvi-mitigation) for more details.
