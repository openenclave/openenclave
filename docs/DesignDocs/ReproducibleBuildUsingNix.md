## Design of Nix Build system for OpenEnclave SDK

### Problem Description.

In the software supply line, the most difficult phase to detect and defend from attackers is the build process. 
Detection of attacks can be greatly improved by ensuring a constant output from the build process, which can
be inspected by comparing to a known sha256sum for the package.

Recently, Debian as attempted to reach this level of reproducibility but that effort appears to have peaked.
Other distro vendors have not tried to do so. Even if the package contents are reproducible, the packaging tools 
do not produce a reproducible result.  This goes for deb and rpm at least.

In addition to reproducibilty, a secure build requires that the source, environment and build process of all of the 
dependencies be provable and auditable.  All dependencies should be itemised in the build process in a form 
that is unique to that build, and would immediately show a change if some part of the project or its
dependencies was modified.  

Current package systems don't support this level of auditability. Currently, the only relationship between an
application and its dependents is given by the filename. The only provable relationship between a .deb and .debs
package is again given by the filename, with no way whatsoever of proving that source produced that binary, or 
how it did it.

High security applications using the Open Enclave SDK require a highly auditable and reproducible build process. They
are able to trade off some effort and time for this end.

### Proposed Approach:

The Nix package system provides all of these guarantees. It has been proposed by partners as at least an excellent
way to bridge the gap between current practice and reproducable, auditable software.

It is not practical to change the package system for major distros. For the forseeable future a piece of 
software needs to be presented in .deb or .rpm packages and the distros build on those package systems.  But 
the build of those packages can be done in a more secure manner using a hybrid approach of building deb packages 
in nix, eventually adding the nix expressions into a curated nix fork.

Nix is essentially a single user system. There is only one nix store and attempts to multi-use it by delegating updates 
to a daemon have been prone to artifacts. We propose to use nix as a single user system, in docker containers. The 
docker container allows the nix system to be encapsulated, and add some additional stability and isolation.

#### Benefits

- Nix is based on services that can be implemented privately, or over the network, or allowed to default to public 
  services with very small changes in configuration or even command lines. This makes the system flexible and resilient.

- The nix programming language allows very complex vetting steps to be introduced in the build process without 
  the need for massive retooling.

- Auditability is inherent to the system. Other than rewriting nix itself, it would be difficult to introduce 
  stealth dependencies or corrupt building tools.

#### Limitations

- Nix package versions are a function of the nixpkgs branch contents. In principle, Nix allows packages to specify
  the versions of dependents by git tag, url, or git commit. In practice that only works in cases where the source
  is not patched and other processing steps are not performed.  If dependent package versions are overridden, 
  they must be built on each project rebuild. The nix store will contain the previous builds once packages are built 
  so that helps considerably if the store is saved.

- The trust level for packages produced by nix is defined by the trust level of the source and the nixpkgs repo.
  There is no vetting agency examining the build outputs to ensure no malware was introduced. That said, if we wish
  that the contents of the nixpkgs repo are completely transparent as is the build process.  The only exception to
  that is the bootstrap-tools package which gets a prebuilt bash, gcc and minimum environment to perform the initial
  build of the contents of bootstrap-tools.  This in turn only occurs when performing a complete build of a nixpkgs
  branch cache.

- The nix project is community based. Its not clear there are any "employees" as such.  The nix project itself is 
  somewhat unclear on its goals, but it generally wants to be a distro (nixos.org) based on the nixpkgs repo and 
  nix build system.  The nixpkgs repo is heavily exercised before release, but industrial levels of quality and 
  reliability are not required.  From what I can tell, though, the results are comparable to other package systems.
  
- There is a very steep learning curve for nix, which is exacerbated by very informal tutorials and advice. The upside
  is there is tutorials and advice and the more the tool is used the more it is understood.

### Required Background: Nix short description:

Nix was originally defined by Eelco Dolstra and described in his thesis, https://nixos.org/~eelco/pubs/phd-thesis.pdf.
The key concept is the idea of a build process as function. Dependencies can then be viewed as the composition
of a series of functional expressions.  The inputs of the build process function can be measured via sha256 sums
and if the function is reproducible (or invariant) the outputs also can be measured and that measurment compared to
known values. So, barring problems in the build tools that interfere with reproduciblity, a given expression will always
produce the same output, provable by a sha256sum.

Nix also controls visibility to build dependencies.  There is no possibilty of a covert package making its 
way into the build because all of the sources, libraries, and tools used in the process must be declared in the
build expression. 

Because all inputs are accounted for by design, auditability is built in. It is possible to reproduce the entire build
of a project, its dependent libaries and tools from source with a single command line argument.

Nix expressions are kept in a git repo, github.com/nixos/nixpkgs. In principle a single version of each package
is contained in the repo, so it is not necessary to specify package versions.  In practice these versions can be
overridden, but that comes at a cost and is not recommended unless there is no option.

The selection of packages (build outputs) in turn is defined by the branch and fork of the nix repo clone which
you are using.

Since the build outputs are measured, producing globally unique names, built versions can be cached. By default, 
there is a global cache at https://cache.nixos.org which contains cached built derivations for the officially 
released packages.  It is not necessary to use this cache. The cache protocol is a simple HTTP get/put protocol, so
any url that points to the correct heirarchy can be used. If no prebuilt version of a package is available at
the cache, the package will be built. Since the package has a fixed output, there is no difference in output
using the cached version or one custom built.

#### Language:

Nix is a language which looks much like Haskell. It is a Haskell derivitive in the same sense that
Java is a C++ derivitive, which is to say it carries over syntactic conventions but not strictly or
completely, and adds some features not in Haskell.

The basis for the language is the function.  A function is an expression which returns a value, the value can
be a singleton (for example integer), set (indicated by curly braces {}), or list (indicated by brackets []). Functions
may include functions. They must be declared in the "let" section of the declaration.  Functions are called only 
when referenced and reduced to values.

When you see what appears to be regular code with braces and a series of semicolon separators is actually a set
being used as an argument.

There are no variables, just functions returning contants. Datatypes are a property of values, but once declared
the function has a constant datatype. function results can be transformed but there is no casting as such. The `let`
clause is where a number of functions can be declared. The `in` clause is where they are used.

```
let
    # function returning an integer:
    three = 3;
    # function returning a set. Set members are retrieved through the dot operator, so myset."one":
    myset = { one = 1; two = 2; three = 3; }
    #
    mylist = [ "one", "two", "three" ];
in 
     
```

if then else exists, but the form is similar to the C conditional,  if <cond> then <alt1> else <alt2> where cond,
alt1 and alt2 are all function calls.  if returns a value.

```
    arch = if platform ? arch then platform.arch else "x86_64-linux"
```
  
There is no sequencing as such. Functions are composed through expression evaluation, so the expression:
```
    this that the_other 
```
will execute the function "the_other" and return its value as an argument to "that" which in turn returns its value to
"this".  There are various caching facilities, so it's possible that one or more of those arguments will be 
replaced with a cached evaluation of the functions. 

Because of that part, there is no idea of "file io" in nix.  Even builtins.trace does not provide assurances of when 
the "print" will actually be evaluated.  

There are no loops in nix. The functionality of the loop is replaced by the map function. 

### Nix data flow.

The nix building process starts out with a nix expression. The expression is located in a file which is 
specified to the nix-instantiate tool, or on the command line. The instantiation process binds the 
dependencies specified by the expression (in buildInputs or checkInputs) to the concrete resources offered by
the nix repo, which specifies the universe of packages available, calculates a sha256 signature for the built product, 
then places the concretised expression into the nix store as a derivation.

```
nix-instantiate -I/home/azureuser/ default.nix
```

A trivial example of a nix expression:
```
with (import <nixpkgs>) {};

let
  # Use the let-in clause to assign the derivation to a variable
  myScript = pkgs.writeShellScriptBin "helloWorld" "echo Hello World";
in
stdenv.mkDerivation rec {
  name = "test-environment";

  src = ./.;
  # Add the derivation to the PATH
  buildInputs = [ myScript ];

  installPhase =
  ''
       mkdir $out
       cp -r ${myScript} $out/
  '';
}
```
  
In the above, "let" is the initialisation/declaration part of the expression. The actual expression proper begins after
"in".  The "rec" keyword is used to allow the function definition to be visible to itself.

nix-instantiate will produce the store derivation in the file :
```
/nix/store/znmj0axqf4v5mjwswd9bq3dvxf0jcsah-test-environment.drv
```
which will contain the nix expression with all attributes assigned with concrete values:
```
Derive ( [ ( "out"
           , "/nix/store/7v249vqann9jrnvb40wri7x4kqr38rp2-test-environment"
           , ""
           , "" ) ]
       , [ ( "/nix/store/029h9shccppyiw1l7qsk6xp0grxgzzbb-stdenv-linux.drv"
           , ["out"] )
         , ( "/nix/store/20vwa6qpx8w3ar66x1fmrjlwy86c7b71-bash-4.4-p23.drv"
           , ["out"] )
         , ( "/nix/store/nhfvqin361648cnwi3v327jsw9gz48ah-helloWorld.drv"
           , ["out"] ) ]
       , [ "/nix/store/9krlzvny65gdc8s7kpb6lkx8cd02c25b-default-builder.sh"
         , "/nix/store/l99yzhb3ngxyrfnmglmh98p7f602id2r-xxx" ]
       , "x86_64-linux"
       , "/nix/store/hrpvwkjz04s9i4nmli843hyw9z4pwhww-bash-4.4-p23/bin/bash"
       , [ "-e"
         , "/nix/store/9krlzvny65gdc8s7kpb6lkx8cd02c25b-default-builder.sh" ]
       , [ ( "buildInputs"
           , "/nix/store/qsgajw2yhrf33qgibsvd9y8zaw64w7j7-helloWorld" )
         , ( "builder"
           , "/nix/store/hrpvwkjz04s9i4nmli843hyw9z4pwhww-bash-4.4-p23/bin/bash" )
         , ("configureFlags", "")
         , ("depsBuildBuild", "")
         , ("depsBuildBuildPropagated", "")
         , ("depsBuildTarget", "")
         , ("depsBuildTargetPropagated", "")
         , ("depsHostHost", "")
         , ("depsHostHostPropagated", "")
         , ("depsTargetTarget", "")
         , ("depsTargetTargetPropagated", "")
         , ("doCheck", "")
         , ("doInstallCheck", "")
         , ( "installPhase"
           , "mkdir $out\ncp -r /nix/store/qsgajw2yhrf33qgibsvd9y8zaw64w7j7-helloWorld $out/\n" )
         , ("name", "test-environment")
         , ("nativeBuildInputs", "")
         , ( "out"
           , "/nix/store/7v249vqann9jrnvb40wri7x4kqr38rp2-test-environment" )
         , ("outputs", "out")
         , ("patches", "")
         , ("propagatedBuildInputs", "")
         , ("propagatedNativeBuildInputs", "")
         , ("src", "/nix/store/l99yzhb3ngxyrfnmglmh98p7f602id2r-xxx")
         , ( "stdenv"
           , "/nix/store/sm7kk5n84vaisqvhk1yfsjqls50j8s0m-stdenv-linux" )
         , ("strictDeps", "")
         , ("system", "x86_64-linux") ] )
```

The derivation can then be used to build the output using either
```
   nix-store --realize
```
or more compactly
```
   nix-build test-environment 
```
will perform both instantiate and realise. The result is a build output located in the nix-store.
```
/nix/store/syibqm72433pzxd46hyw3xbr5swq286j-test-environment
```
which contains:
```
$ ls /nix/store/syibqm72433pzxd46hyw3xbr5swq286j-test-environment
qsgajw2yhrf33qgibsvd9y8zaw64w7j7-helloWorld
```
which in turn contains the helloWorld script.

For more involved build project the build actions are clearly more complex, but the flow is the same.

### The Nix Repo

To build, a clone of the nix packages repo must be present. There is a default clone installed when nix 
is installed. 

The nix packages repo serves two purposes, somewhat at odds with each other.

- The package repository for a linux distro "NixOS" which will eventully be a standalone distro. In that 
  case packages are chosen for release branches with an eye to mutual compatibility and working well within
  that defined universe.  

- The package repository is also used for producing packages for other linux distros (ubuntu, debian,
  redhat, fedora, arch, gentoo) with easily auditable dependencies. In this case, it is necessary to
  consider specific compatible versions of packages.  In particular, glibc must be an equal or older
  revision than the glibc of the platform or the program will not dynamically link.  This is by design.
  Ubuntu 18.04 is limited to glibc 2.27. The current lts release 20.04 usues glibc 2.31 and fedora 33 
  uses libc-2.32.  The nixpkgs branch release-20.09 is based on glibc 2.32.  The somewhat older branch
  20.03 uses libc-2.30 so can work on the current common distros, including the current rhel.  

  While it is not difficult to change the version of glibc in a custom repo branch, since glibc is linked 
  by every package, to do so would require a custom repo build. In that case, it would require a custom 
  cache to provide prebuilding, or everything would require everything be built from source.
``

### Caching and Hydra

The official branches in nixpkgs are prebuilt and available at cache.nixos.org. Caching is keyed to the build outputs
sha digest, so custom environments will be able to use those prebuilts so long as no changes have been made. 
If any changes are made to that package, any package related to the changed package will need to be custom
built and cached in nix store.


## A Nix build system for OpenEnclave SDK

We propose to add an optional nix based build environment for OpenEnclave SDK using docker containers.

This would consist of :
- Dockerfile.nix and build-oe-nix-build.sh for building the oe nix docker image locally.
- build_openenclave.sh for building the oe deb package via a nix environment.
- Dockerfile.test and test-oe-nix-build.sh for verifying that package is functional.

The process builds a reproducible .deb package of openenclave-sdk. 

This process can be integrated with ADO or CPDX CI, but that is not part of this submission. We do not currently
recommend depending exclusively on a nix environment for production packaging and CI.

### Dockerfile.nix

The dockerfile is passed up to four build args:

 - BASE_IMAGE allows for different os base images, in particular it allows the substitution of a
   CPDX base image rather than the generic ubuntu 20.04. As was previously mentioned, we are basing on 
   ubuntu 20.04 because package versions align best with nixpkgs release-20.03.

 - BUILD_USER, BUILD_USER_ID, BUILD_USER_HOME need to be set together.
   Reproducibility requires a standard build user, since the tar directory entries in the deb package include 
   user and group information.  We default to "azureuser" "1000" "/home/azureuser"

The script "build-oe-nix-image.sh" is a thin wrapper. It takes no arguments, and just passes the needed arguments
to docker build.  If it needs to be modified, a new script should be created.

Dockerfile.nix prepares the build image by:

- adding via apt minimum packages for the outer image. This includes a text editor (vim) and ELF patch utility (patchelf).

- sets up nit configuration.

- diables apt.

- creates the build user and directories, groups etc.

- creates a nix expression for building openenclave via (shell.nix).

- installs nix as the build user

- calls the prep-nix-build.sh script which sets up the git clone of nix pkgs and preinstalls the package
  derivations needed for building openenclave into the nix store. The search process for dependencies in
  nix is to refer to the nix store first, before looking at nixpkgs or contacting the cache if enabled. While
  we cannot select package versions from the expression, but must depend on the nixpkgs repo to provide the
  correct versions, we can prime the nix store to provide the exact derivation we wish before referring to the repo.

  These derivations have been manually chosen.  This also allows us to set package priorities which is required
  between packages that provide overlapping contents, for example clang_7 and llvm_7.

- adds a build.env file which contains environment values to control the build.  This is not part of the 
  - REV is the git revision (commit or tag) to pull for the build.
  - SHA is the sha256 hash of the tar file downloaded from git.
  - DO_CHECK enables ctests as part of the build.
  - DEB_SHA specifies the expected result sha25sum for the .deb file produced. An error will be thrown if the 
    sha is incorrect. If not set, the sha is not checked.

- adds needed files for ctest to the .nix_libs directory, which will be referred to by ctest. Nix expressions
  cannot refer to libraries outside the minimum environment and explicit inputs, so these libraries are needed
  to use sgx (and eventually TrustZone) facilties.

- sets the build user as the user. Among other things, this means the build image when run cannot be 
  modified by the addition of apt packages.

The resulting image is named openenclave-build. It can (and should) be generated once and pushed into a common 
repo.

### build_openenclave.sh

Runs the image produced by docker build, with arguments resolved.
The output of the process is a .deb and a .nar file containing an exported nix store for use in developing 
openenclave sdk apps using nix.


### workflow

```
   ./build-oe-nix-image.sh
```
will build the nix docker image. This can be pushed:
```
   docker push openenclave-build
```
and later pulled, or just used locally.

To build the openenclave sdk 
```
   ./build_openenclave.sh -o ./result
```
will build the oe deb and nix-store and place it in ./result. By default it will run ctests. If the
sha of the resulting package is specified, it will compare the .deb sha25sum to the specified value.
At the end of the process the deb package will not contain any run time evidence of coming from 
a nix environment.


### Files:

The dockerfiles, scripts , and container resident files are located in the directory openenclave/reproducible.
