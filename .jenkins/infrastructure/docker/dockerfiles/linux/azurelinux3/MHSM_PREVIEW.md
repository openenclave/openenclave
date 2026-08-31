# MHSM Azure Linux 3 and OpenSSL 3.5 integration preview

The `openenclave-mhsm-azl3-openssl35` image contains Azure Linux 3, an Open Enclave SDK built from the same revision, OpenSSL 3.5.7 enclave crypto, Clang, CMake, Ninja, and Intel's Azure Linux 3 SGX/DCAP packages.

## Enable the pipeline

After this change is merged, run `/Private/Infrastructure/Build-Docker-Images` with:

- `BUILD_LINUX=true`
- `BUILD_WINDOWS=false` unless Windows images are also required
- `BUILD_AZL3_MHSM_PREVIEW=true`
- `BRANCH_NAME=master`
- `DOCKER_TAG=<versioned-tag>`
- `TAG_LATEST=false` for validation builds
- `PUBLISH=false` to skip promotion and version metadata, or `PUBLISH=true` to promote the image and update `DOCKER_IMAGES.md`

The parent pipeline forwards the preview flag to `/Private/Infrastructure/Linux-Docker-Container-Build`. That job builds and pushes both `oetools-azl3:<versioned-tag>` and `openenclave-mhsm-azl3-openssl35:<versioned-tag>`, then archives `openenclave-azl3-openssl35-<versioned-tag>.tar.gz`. The versioned images are pushed by the build job even when `PUBLISH=false`.

Before merge, create a temporary Pipeline job or use Jenkins Replay so the job loads `.jenkins/infrastructure/docker/build_linux_docker_images.Jenkinsfile` from `PallabPaul/openenclave:azurelinux3-ci-image`. Then run it with:

- `REPOSITORY_NAME=PallabPaul/openenclave`
- `BRANCH_NAME=azurelinux3-ci-image`
- `BUILD_AZL3_MHSM_PREVIEW=true`
- `DOCKER_TAG=<validation-tag>`
- `TAG_LATEST=false`

Use an agent with Docker and managed-identity access to the target ACR. SGX devices are optional for building the image; the pipeline runs the hardware smoke test only when both SGX devices are present.

## Use with the MHSM build container

The preview image validates the Open Enclave SDK and Intel SGX/DCAP layer. It also includes the standard build tools, .NET 8 SDK, pinned OCaml 4.14.2 toolchain, and Azure Linux kernel development headers required by MHSM's local build.

Copy the archived `openenclave` directory into the Azure Linux 3 MHSM build-container context at `/opt/openenclave`. The resulting container satisfies the path used by the MHSM root `CMakeLists.txt`:

```cmake
set(OpenEnclave_DIR /opt/openenclave/lib/openenclave/cmake/ CACHE PATH "Location of OE CMake config")
```

The preview image build runs a CMake smoke project that requires the OE targets used by MHSM: `oehost`, `oeenclave`, `oelibc`, `oelibcxx`, `oecryptoopenssl_3`, `oeedger8r`, and `oesign`.

The following MHSM `develop` build paths were validated in the preview image with the repository's central NuGet feed authenticated:

- the complete `external/build_clean.sh` dependency build, including four Marvell kernel modules built for Azure Linux kernel `6.6.150.1-1.azl3`;
- OCaml generation and compilation of `stubger8r`;
- the native `cfm_native` dependency graph;
- the root Debug build, including HSM bootstrap and HSM Node Agent outputs;
- all tests registered by the Azure Linux 3 build: `test_hsm_bootstrap.UnitTests` and `HsmNodeAgent.UnitTests`.

The image was also validated on a native Azure Linux 3 `Standard_DC2s_v3` host. With `/dev/sgx_enclave` and `/dev/sgx_provision` mounted, `oesgx` detected SGX2, Flexible Launch Control, Key Sharing and Separation, and 8 GiB of EPC.

The external build requires the accompanying MHSM compatibility change that replaces the deprecated `AC_OUTPUT(files)` form in the Marvell 2.09 Autoconf input with `AC_CONFIG_FILES(files)` followed by `AC_OUTPUT`.

After adding the SDK layer to the existing MHSM build container, use the repository's normal local build flow:

```bash
cd external
./build_clean.sh
cd ..
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel "$(nproc)"
ctest --test-dir build --output-on-failure
```

The image can compile Marvell modules from WSL against its pinned Azure Linux kernel headers, but loading modules and running SGX workloads still require a native Azure Linux host. The MHSM repository currently disables enclave targets on Azure Linux 3. Remove that temporary gate in the corresponding MHSM change only after hardware validation passes on an SGX-capable host.

## Build a derived workload image

```dockerfile
ARG OE_MHSM_IMAGE=openenclave.azurecr.io/openenclave-mhsm-azl3-openssl35:<version>
FROM ${OE_MHSM_IMAGE}

WORKDIR /workload
COPY . .
RUN cmake -S . -B build -G Ninja \
    -DCMAKE_PREFIX_PATH=/opt/openenclave \
    && cmake --build build --parallel

CMD ["/workload/build/<mhsm-host>"]
```

Run a hardware workload with the SGX devices and AESM socket:

```text
docker run --rm \
  --device /dev/sgx_enclave:/dev/sgx_enclave \
  --device /dev/sgx_provision:/dev/sgx_provision \
  --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
  <mhsm-workload-image>
```

## Preview boundary

This is an integration preview. Production promotion still requires MHSM regression testing, an SGX-capable Azure Linux 3 agent run, Azure-approved DCAP collateral configuration, vulnerability and licensing review, image signing, and a pinned package baseline with a rollback plan.
