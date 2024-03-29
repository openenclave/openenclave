# Advanced Build Information

## 1. Installing CMake

This project requires at least [CMake 3.12](https://cmake.org/download/). This
is probably not available in your package manager's repositories, but we use the
`OBJECT` library feature extensively, so you need to install it either manually
from their website, or with our Ansible scripts:

```bash
cd openenclave/scripts/ansible
ansible localhost -m import_role -a "name=linux/openenclave tasks_from=environment-setup.yml" --become --ask-become-pass
```

## 2. CMake Configuration

In addition to the standard CMake variables, the following CMake variables
control the behavior of the Linux make generator for Open Enclave:

| Variable                 | Description                                          |
|--------------------------|------------------------------------------------------|
| CMAKE_BUILD_TYPE         | Build configuration (*Debug*, *Release*, *RelWithDebInfo*). Default is *Debug*. |
| ENABLE_FULL_LIBCXX_TESTS | Enable full Libc++ tests. Default is disabled, enable with setting to "On", "1", ... |
| ENABLE_REFMAN            | Enable building of reference manual. Requires Doxygen to be installed. Default is disabled, enable with setting to "On", "1", ... |

For example, to generate an optimized release-build with debug info, run the following
from your build subfolder:

```bash
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
```

The following build types cause the C macro `NDEBUG` to be defined:

- `CMAKE_BUILD_TYPE="Release"`
- `CMAKE_BUILD_TYPE="RelWithDebInfo"`

whereas `CMAKE_BUILD_TYPE="Debug"` causes it to be undefined. Defining the
`NDEBUG` macro affects the behavior of Open Enclave in three ways:

- The `oe_assert()` and `assert()` macros become no-ops.
- The `oe_backtrace()` function returns an empty backtrace.
- The debug allocator is disabled. The debug allocator checks for memory errors
during enclave termination.

Multiple variables can be defined in the cmake call with multiple "-D*Var*=*Value*" arguments.

## 3. Building

Once CMake has run and the build is configured, build with:

```bash
make
```

This builds the entire Open Enclave SDK, creating the following files in your build folder.

| Filename                          | Description                                           |
|-----------------------------------|-------------------------------------------------------|
| output/bin/oegdb                  | Utility for debugging enclaves                        |
| output/bin/oesgx                  | Utility for determining the level of SGX support for the given platform |
| output/bin/oesign                 | Utility for signing enclaves                          |
| output/lib/enclave/liboecore.a    | Core library for building enclave applications (defines enclave intrinsics) |
| output/lib/enclave/liboeenclave.a | Enclave library for building enclave applications (defines enclave features) |
| output/lib/enclave/liboelibc.a    | C runtime library for enclave                         |
| output/enclave/liboelibcxx.a      | C++ runtime library for enclave                       |
| output/lib/host/liboehost.a       | Library for building host applications                |
| output/share/doc/openenclave/     | HTML API reference for Open Enclave                   |
| tools/oeedger8r/oeedger8r         | Utility for generating ECALL and OCALL stubs from IDL |

If there is a build failure, set the `VERBOSE` make variable to print all invoked commands.

```bash
make VERBOSE=1
```

Building from within a subtree of the build-tree builds all dependencies for that directory as well.
`make clean` is handy before a spot-rebuild in verbose mode.

A successful build only outputs the HTML API reference into the build-tree.
To update the Doxygen-generated documentation published to https://openenclave.github.io/openenclave,
please follow instructions [here](/docs/refman/doxygen-howto.md)

## 4. Visualizing the CMake Dependency Graph

CMake comes with [built-in support for
graphviz](https://cmake.org/cmake/help/latest/module/CMakeGraphVizOptions.html)
which makes it easy to generate an image of the dependency graph for a CMake
project. For example, to visualize the entire Open Enclave project from the
CMake root:

```bash
mkdir graphviz && cd graphviz
cmake --graphviz=graph ..
dot graph -Tsvg -o graph.svg
```

Although other output image formats such as PNG are support, we recommend using
SVG because it keeps the resulting file size reasonably small in spite of the
huge number of nodes (targets) in the resulting graph.

To change the ignored targets, edit the file named `CMakeGraphVizOptions.cmake`
at the root of the repo.

As of 2020-03-10, it looks like this:

![CMake Dependency Graph](/docs/GettingStartedDocs/DependencyGraph.svg)

### Legend

Nodes:

- square: interface or shared library
- diamond: static library
- circle: external library (static or shared)
- house: executable

Edges:

- solid: public dependency
- dotted: interface dependency
- dashed: private dependency

## 5. LVI Mitigation

In response to the [LVI vulnerability](https://software.intel.com/security-software-guidance/software-guidance/load-value-injection), Open Enclave SDK provides two mutually exclusive mitigation methods: one adopts the mitigation based on [Intel's prebuilt as/ld binaries
](https://01.org/intel-software-guard-extensions/downloads) - code name ControlFlow-GNU (default option), and the other adopts the LVI mitigation that comes with Clang 11 or newer - code name ControlFlow-Clang.

### 5.1 LVI Mitigation #1 - ControlFlow-GNU

This LVI mitigation method adopts the mitigation based on [Intel's prebuilt as/ld binaries
](https://01.org/intel-software-guard-extensions/downloads). Some scripts (see below) have been provided to easily configure Open Enclave to use these custom toolchain.

### 5.1.1 Newly Added Files

The following list includes necessary files for Open Enclave SDK to support this LVI mitigation method on both Linux and Windows.

| Filename                          | Description                                           |
|-----------------------------------|-------------------------------------------------------|
| scripts/lvi-mitigation/install_lvi_mitigation_bindir | Script for installing necessary compilation tools (Linux). |
| scripts/lvi-mitigation/generate_wrapper              | Script for generating compiler wrappers, needed by installation (Linux). |
| scripts/lvi-mitigation/invoke_compiler               | Script for invoking compilers, needed by generated wrappers (Linux). |
| scripts/lvi-mitigation/lvi-mitigation.py             | Python script for supporting mitigation (Windows). |

### 5.1.2 Dependency Installation

#### 5.1.2.1 Linux

On Linux, run the [install_lvi_mitigation_bindir](/scripts/lvi-mitigation/install_lvi_mitigation_bindir) script
to install the dependencies to a desired location.
The following example creates a directory `lvi_mitigation_bin` with all the dependencies in the root of the
openenclave directory.

```bash
# In the /home/yourname/openenclave directory.
~/openenclave$ ./scripts/lvi-mitigation/install_lvi_mitigation_bindir
Do you want to install in current directory? [yes/no]: yes
...
Installed: /home/yourname/openenclave/lvi_mitigation_bin
```

If the script ran successfully, the `lvi_mitigation_bin` should contain a list of files:

```bash
~/openenclave/lvi_mitigation_bin$ ls -l
total 16
-rwxrwxr-x 1 yourname yourname 2121936 Mar  10 10:00 as
-rwxrwxr-x 1 yourname yourname     233 Mar  10 10:00 clang++-11
lrwxrwxrwx 1 yourname yourname      18 Mar  10 10:00 clang++-11_symlink -> /usr/bin/clang++-11
-rwxrwxr-x 1 yourname yourname     231 Mar  10 10:00 clang-11
lrwxrwxrwx 1 yourname yourname      16 Mar  10 10:00 clang-11_symlink -> /usr/bin/clang-11
-rwxrwxr-x 1 yourname yourname     227 Mar  10 10:00 g++
lrwxrwxrwx 1 yourname yourname      12 Mar  10 10:00 g++_symlink -> /usr/bin/g++
-rwxrwxr-x 1 yourname yourname     227 Mar  10 10:00 gcc
lrwxrwxrwx 1 yourname yourname      12 Mar  10 10:00 gcc_symlink -> /usr/bin/gcc
-rwxrwxr-x 1 yourname yourname    1093 Mar  10 10:00 invoke_compiler
-rwxrwxr-x 1 yourname yourname 2722256 Mar  10 10:00 ld
```

`as` and `ld` are the customized GNU assembler and linker obtained from Intel, which support the
LVI mitigation. `clang-11`, `clang++-11`, `gcc`, and `g++` are the copies of previously shown wrappers that invoke the
customized `as` and `ld` when compiling enclave code with LVI mitigation. The remaining files with the `_symlink`
suffix link to the actual compilers installed in the system, which are required by the wrappers.

**Note**: `clang-11` and `clang++-11` may be missing if the system does not have the `clang` version 11 installed. If you encounter this, you will need to install Clang as GCC is not supported.

**Note**:  While `clang-11` is our supported and recommended version, Open Enclave may be built with `clang-10` as well.

**Note**: If the version of `glibc` is older than `2.27`, the `ld` will be missing in the above output.
Consequently, `ld` will not be installed. Without a compatible version of `ld`,
debug symbol generation (i.e. use of the `-g` option) cannot be used when compiling with LVI mitigation.

Example of checking the version of `glibc`

```bash
ldd --version | awk '/ldd/{print $NF}'
```

#### 5.1.2.2 Windows

On Windows, this step is not required. Instead of using the customized assembler and linker, the Windows build
uses the [Python script](/scripts/lvi-mitigation/lvi-mitigation.py)
(modified based on the Intel's version) to instrument the enclave code at
the assembly level that achieves similar functionality.

### 5.1.3 CMake Configuration

Open Enclave SDK adds two CMake variables that allow developers to build enclave libraries
with LVI mitigation:

| Variable                 | Description                                          |
|--------------------------|------------------------------------------------------|
| LVI_MITIGATION           | Enable LVI mitigation to trusted code. The only currently supported values are `None`, `ControlFlow`, `ControlFlow-GNU` and `ControlFlow-Clang`. Currently `ControlFlow` is an alias for `ControlFlow-GNU` |
| LVI_MITIGATION_BINDIR    | (Linux-only) Path to the customized compilation toolchain required by the LVI Mitigation.  Not required if using `ControlFlow-Clang`  |

#### Linux

On Linux, the following example configures the build with LVI mitigation (specify the `LVI_MITIGATION_BINDIR` to the directory created in the previous step).

```bash
cmake .. -DLVI_MITIGATION=ControlFlow -DLVI_MITIGATION_BINDIR=/home/yourname/openenclave/lvi_mitigation_bin
```

#### Windows

On Windows, only `LVI_MITIGATION` is required.

```bash
cmake .. -DLVI_MITIGATION=ControlFlow
```

### 5.2 LVI Mitigation #2 - ControlFlow-Clang

This LVI mitigation method uses [an option provided by Clang version 11 and later](https://releases.llvm.org/11.0.0/tools/clang/docs/ClangCommandLineReference.html#cmdoption-clang-mlvi-cfi).

### 5.2.1 Dependency Installation

Install Clang version 11 from a method of your choice.

> Open Enclave does not support newer version, so you need to install Clang major version 11.

### 5.2.2 CMake Configuration

To enable this LVI mitigation method, set CMake variable `LVI_MITIGATION` to `ControlFlow-Clang`.

```bash
cmake .. -DLVI_MITIGATION=ControlFlow-Clang
```

## 5.3 Building

Once CMake has run, and the build is configured, build with:

```bash
make
```

With the LVI mitigation options specified, `make` generates LVI-mitigated versions of all enclave libraries
in addition to the regular versions of them. For example:

| Filename                          | Description                                           |
|-----------------------------------|-------------------------------------------------------|
| output/lib/enclave/liboecore.a    | Core library for building enclave applications (defines enclave intrinsics). |
| output/lib/enclave/liboecore-lvi-cfg.a    | Core library with LVI mitigation. |
| output/lib/enclave/liboeenclave.a | Enclave library for building enclave applications (defines enclave features). |
| output/lib/enclave/liboeenclave-lvi-cfg.a | Enclave library with LVI mitigation. |
| output/lib/enclave/liboelibc.a    | C runtime library for enclave.                         |
| output/lib/enclave/liboelibc-lvi-cfg.a    | C runtime library with LVI mitigation.         |
| output/enclave/liboelibcxx.a      | C++ runtime library for enclave.                       |
| output/enclave/liboelibcxx-lvi-cfg.a      | C++ runtime library with LVI mitigation.       |

## 5.4 Dependency Graph with LVI Mitigation

To get the dependency graph with LVI mitigation enabled, run

```bash
mkdir graphviz && cd graphviz
cmake --graphviz=graph .. -DLVI_MITIGATION=ControlFlow \
-DLVI_MITIGATION_BINDIR=/home/yourname/openenclave/lvi_mitigation_bin
dot graph -Tsvg -o graph-lvi-cfg.svg
```

As of 2020-03-10, it looks like this:

![CMake Dependency Graph with LVI Mitigation](/docs/GettingStartedDocs/DependencyGraphLVICFG.svg)

## 5.5 Building Enclaves with LVI Mitigation

With the LVI mitigation enabled, Open Enclave SDK provides a new option that
allows users to build enclaves on top of the mitigated version of libraries.

See [Build and Run samples with LVI mitigation](/samples/helloworld/README.md#build-and-run-with-LVI-mitigation).
