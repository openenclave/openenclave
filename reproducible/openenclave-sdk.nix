{ pkgs ? import <nixpkgs> {} 
    ,  REV  ? "HEAD" 
    ,  SHA  ? "0000000000000000000000000000000000000000000000000000" 
    ,  DEB_SHA ? ""
    }:   

with pkgs; 
    stdenvNoCC.mkDerivation {  
        name = "openenclave-sdk";  
        nativeBuildInputs = with pkgs;  [  
       	    pkgs.cmake 
       	    pkgs.llvm_7 
            pkgs.clang_7 
            pkgs.python3 
            pkgs.doxygen 
            pkgs.dpkg 
        ];  
        buildInputs = with pkgs;  [ pkgs.openssl ];  
        checkInputs = with pkgs;  [ pkgs.strace pkgs.gdb ];  
        src = fetchFromGitHub { 
                      owner = "openenclave";
                      repo = "openenclave";
                      rev  = REV; 
                      sha256 = SHA; 
                      fetchSubmodules = true; 
                }; 
  
        CC = "clang";
        CXX = "clang++";
        LD = "ld.lld";
        CFLAGS="-Wno-unused-command-line-argument";
        CXXFLAGS="-Wno-unused-command-line-argument";
        NIX_ENFORCE_PURITY=0; 
        NIX_ENFORCE_NO_NATIVE=0; 
        doCheck = false; /* We do the test phase in nix-shell */ 
        dontStrip = true;
        dontPatchELF = true;
        doFixup = false;
        configurePhase = '' 
                chmod -R a+rw $src 
                mkdir -p $out 
                cd $out 
                $OE_SIMULATION cmake -G "Unix Makefiles" $src -DCMAKE_BUILD_TYPE=RelWithDebInfo  
            ''; 
  
        buildPhase = '' 
                make VERBOSE=1 -j 4 
            ''; 
        checkPhase = '' 
                /* We must include something in the check phase or it will default */ 
                echo "ctest performed in nix-shell " 
            ''; 

        installPhase = '' 
                echo "install phase skipped " 
            ''; 

        fixupPhase = '' 
                echo "fixup phase skipped " 
            ''; 
        
        shellHook = '' 

                cd $out
                chmod -Rf a+w .

                echo "=== ctest -E samples\|oegdb-test\|report" 
                if $DO_CHECK
                then 
                    find ./tests -type d -exec chmod a+w {} \;

                    LD_LIBRARY_PATH=/home/azureuser/.nix_libs ctest -E samples\|oegdb-test\|report | tee /output/test-report-$(date +%Y%j%H%M)
                    CTEST_RESULT=$?
                    if [ $CTEST_RESULT -ne 0 ]
                    then
                        echo "ERROR: Ctests failed"
                        exit $CTEST_RESULT
                    fi
                fi

		if $DEB_PACKAGE 
                then
                    if [ $(uname -m) == "aarch64" ]
                    then 
                        LD_INTERPRETER="/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
                    elif [ $(uname -m) == "x86_64" ]
                    then
                        LD_INTERPRETER="/lib64/ld-linux-x86-64.so.2"
                    else
                        LD_INTERPRETER="UNSUPPORTED ARCHITECTURE"
                    fi

                    echo "=== FIXUP $LD_INTERPRETER"
                    find $out -type f -executable -exec patchelf --set-interpreter $LD_INTERPRETER {} \;
                    find $out -type f -executable -exec patchelf --remove-rpath {} \;
                    echo "=== BUILD DEB PACKAGE"
                    /home/azureuser/build_deb_pkg.sh ${DEB_SHA}
                else 
                    echo "skipping package build" 
                fi
                if $INTERACTIVE_SHELL
                then
                    echo "=== Complete"
                    exit 0
                fi 
            '';  
}  

