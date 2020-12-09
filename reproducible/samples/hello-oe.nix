{ pkgs ? import <nixpkgs> {} 
    ,  REV  ? "HEAD" 
    ,  SHA  ? "0000000000000000000000000000000000000000000000000000" 
    }:   


let
    oe = pkgs.callPackage ./openenclave-sdk.nix { inherit REV SHA; } ;
in
with pkgs; 

    stdenvNoCC.mkDerivation {  
        name = "hello-oe";  
        nativeBuildInputs = with pkgs;  [  
       	    pkgs.cmake 
       	    pkgs.llvm_7 
            pkgs.clang_7 
            pkgs.pkg-config
        ];  

        buildInputs = with pkgs;  [ pkgs.openssl oe ];  
        checkInputs = with pkgs;  [ pkgs.strace pkgs.gdb ];  

        src = fetchFromGitHub { 
                      owner = "openenclave";
                      repo = "openenclave";
                      rev  = REV; 
                      sha256 = SHA; 
                      fetchSubmodules = false; 
                }; 

        configurePhase = '' 
                echo ${oe}
                echo "copy sources from ${src}"
                oe=${oe}
                openssl_pc=$(find /nix/store -name 'openssl.pc' -print)
                PKG_CONFIG_PATH=$(dirname $openssl_pc):${oe}/install/share/pkgconfig
                PATH=$PATH:$oe/install/bin
                mkdir -p $out/helloworld
                pushd $out
                echo "cp -r $src/samples/* ."
                cp -r $src/samples/* .
                chmod -Rf a+w helloworld
                popd
            ''; 
  
        buildPhase = '' 
                echo "skip build"
                pushd $out/helloworld
                make
                popd
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
                echo "Shell hook"
                oe=${oe}


            '';  
}  

