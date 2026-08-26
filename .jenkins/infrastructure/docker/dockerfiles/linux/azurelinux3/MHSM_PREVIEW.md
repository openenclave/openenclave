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

## Consume the image

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
