# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
ARG BASE_IMAGE="ubuntu@sha256:fff16eea1a8ae92867721d90c59a75652ea66d29c05294e6e2f898704bdb8cf1"
FROM $BASE_IMAGE

#
# Build container to produce reproducible nix derivation and .deb package of the OpenEnclave SDK
# 
# Uses nix package manager to wrap the standard build process.
#
# 
#
RUN apt-get update \
        && apt-get install -y curl python3 perl git vim dpkg patchelf \
        && mkdir -p /nix /etc/nix \
        && chmod a+rwx /nix \
        && echo 'sandbox = false\nkeep-derivations = true\nkeep-env-derivations = true' > /etc/nix/nix.conf \
        && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /output
RUN mkdir -p /output/build
RUN chmod -R 777 /output
RUN mkdir -p /opt/openenclave
RUN chmod -R 777 /opt/openenclave
ENV ARCH=$(arch)

#
# We allow overriding these settings, but if one does, the build user and id must match or else the .deb tars won't have 
# a reproducible signature, since tar entries include user and group ownerships.
ARG BUILD_USER=azureuser
ARG BUILD_USER_ID=1000
ARG BUILD_USER_HOME=/home/azureuser

# This will exclude oegdb, samples, and report 
ARG TEST_EXCLUSIONS="-E samples\|oegdb-test\|report"

#add a user for Nix
RUN echo "adduser $BUILD_USER --uid $BUILD_USER_ID --home $BUILD_USER_HOME"
RUN adduser $BUILD_USER --uid $BUILD_USER_ID --home $BUILD_USER_HOME --disabled-password --gecos "" --shell /bin/bash
RUN addgroup nixbld 
RUN adduser $BUILD_USER  nixbld
ENV USER=$BUILD_USER
USER $BUILD_USER
CMD /bin/bash -l
WORKDIR /home/$BUILD_USER
# 
#create the shell config
RUN echo "{ pkgs ? import <nixpkgs> {} \n\
    ,  REV  ? \"HEAD\" \n\
    ,  SHA  ? \"0000000000000000000000000000000000000000000000000000\" \n\
    ,  DO_CHECK  ? false \n\
    ,  OE_SIM ? \"\"  \n\
    ,  INTERACTIVE_SHELL ? \"false\"\n\
    ,  DEB_PACKAGE ? \"true\"\n\
    ,  DEB_SHA ? \"\"\n\
    }:   \n\
\n\
with pkgs; \n\
    stdenvNoCC.mkDerivation {  \n\
        name = \"openenclave-sdk\";  \n\
        nativeBuildInputs = with pkgs;  [  \n\
        	pkgs.cmake \n\
        	pkgs.llvm_7 \n\
        	pkgs.clang_7 \n\
            pkgs.python3 \n\
            pkgs.doxygen \n\
            pkgs.dpkg \n\
        ];  \n\
        buildInputs = with pkgs;  [ pkgs.openssl ];  \n\
        checkInputs = with pkgs;  [ pkgs.strace pkgs.gdb ];  \n\
        src = fetchFromGitHub { \n\
                      owner = \"openenclave\";\n\
                      repo = \"openenclave\";\n\
                      rev  = REV; \n\
                      sha256 = SHA; \n\
                      fetchSubmodules = true; \n\
                }; \n\
  \n\
        CC = \"clang\";\n\
        CXX = \"clang++\";\n\
        LD = \"ld.lld\";\n\
        CFLAGS=\"-Wno-unused-command-line-argument\";\n\
        CXXFLAGS=\"-Wno-unused-command-line-argument\";\n\
        NIX_ENFORCE_PURITY=0; \n\
        NIX_ENFORCE_NO_NATIVE=0; \n\
        doCheck = false; /* We do the test phase in nix-shell */ \n\
        dontStrip = true;\n\
        dontPatchELF = true;\n\
        doFixup = false;\n\
        configurePhase = '' \n\
                chmod -R a+rw \$src \n\
                mkdir -p \$out \n\
                cd \$out \n\
                \$OE_SIM cmake -G \"Unix Makefiles\" \$src -DCMAKE_BUILD_TYPE=RelWithDebInfo  \n\
            ''; \n\
  \n\
        buildPhase = '' \n\
                echo \$OE_SIMULATION \n\
                make VERBOSE=1 -j 4 \n\
            ''; \n\
        checkPhase = '' \n\
                /* We must include something in the check phase or it will default */ \n\
                echo \"ctest performed in nix-shell \" \n\
            ''; \n\
\n\
        installPhase = '' \n\
                echo \"install phase skipped \" \n\
            ''; \n\
\n\
        fixupPhase = '' \n\
                echo \"fixup phase skipped \" \n\
            ''; \n\
        \n\
        shellHook = '' \n\
\n\
                cd \$out\n\
                chmod -Rf a+w .\n\
\n\
                echo \"=== ctest -E samples\|oegdb-test\|report\" \n\
                if \$DO_CHECK\n\
                then \n\
                    find ./tests -type d -exec chmod a+w {} \;\n\
\n\
                    LD_LIBRARY_PATH=/home/azureuser/.nix_libs \$OE_SIM ctest -E samples\|oegdb-test\|report \n\
                    CTEST_RESULT=\$?\n\
                    if [ \$CTEST_RESULT -ne 0 ]\n\
                    then\n\
                        echo \"ERROR: Ctests failed\"\n\
                        exit \$CTEST_RESULT\n\
                    fi\n\
                fi\n\
\n\
                if [ \$(uname -m) == \"aarch64\" ]\n\
                then \n\
                    LD_INTERPRETER=\"/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1\"\n\
                elif [ \$(uname -m) == \"x86_64\" ]\n\
                then\n\
                    LD_INTERPRETER=\"/lib64/ld-linux-x86-64.so.2\"\n\
                else\n\
                    LD_INTERPRETER=\"UNSUPPORTED ARCHITECTURE\"\n\
                fi\n\
                echo \"=== FIXUP \$LD_INTERPRETER\"\n\
                find \$out -type f -executable -exec patchelf --set-interpreter \$LD_INTERPRETER {} \;\n\
                find \$out -type f -executable -exec patchelf --remove-rpath {} \;\n\
\n\
		if \${DEB_PACKAGE} \n\
                then\n\
                    /home/azureuser/build_deb_pkg.sh \${DEB_SHA}\n\
                else \n\
                    echo \"skipping package build\" \n\
                fi\n\
                if \${INTERACTIVE_SHELL}\n\
                then\n\
                    echo \"=== Complete\"\n\
                    exit 0\n\
                fi \n\
            '';  \n\
}  \n\
" > /home/$BUILD_USER/shell.nix



RUN echo "User is $USER "
#install the required software
#RUN touch .bash_profile \
#
# We add the nix install and packages into the container rather than waiting for run time.
# The packages are then located in the nix store until the next push of the container
ADD ./install-nix.sh /home/$BUILD_USER
RUN  /bin/bash /home/$BUILD_USER/install-nix.sh
ENV NIX_PATH=/home/$BUILD_USER
ADD ./prep-nix-build.sh /home/$BUILD_USER
RUN /bin/bash ./prep-nix-build.sh /home/$BUILD_USER/nixpkgs

ADD ./sort_deb_sum.sh /home/$BUILD_USER
ADD ./nix-build.sh /home/$BUILD_USER
ADD ./nix-shell.sh /home/$BUILD_USER
ADD ./build_deb_pkg.sh /home/$BUILD_USER
RUN mkdir -p /home/$BUILD_USER/.nix_libs
ADD ./nix-libs.tar.gz /tmp
RUN cp /tmp/nix-libs/libsgx_enclave_common.so /home/$BUILD_USER/.nix_libs \
    && cp /tmp/nix-libs/libsgx_enclave_common.so.1 /home/$BUILD_USER/.nix_libs \
    && cp /tmp/nix-libs/libsgx_launch.so.1  /home/$BUILD_USER/.nix_libs \
    && cp /tmp/nix-libs/libprotobuf.so.22  /home/$BUILD_USER/.nix_libs \
    && cp /tmp/nix-libs/libstdc++.so.6  /home/$BUILD_USER/.nix_libs
