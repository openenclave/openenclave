The Open Enclave SDK's oeedger8r
================================

The `oeedger8r` tool is a plugin to Intel SGX's Edger8r. We support the same
Enclave Definition Language syntax, but generate edge routines for use with Open
Enclave.

Building and Running
--------------------

The `oeedger8r` is built as part of the Open Enclave SDK CMake build process,
and shipped in our package.

To build from source, please follow
[Advanced Build Info](../../docs/GettingStartedDocs/Contributors/AdvancedBuildInfo.md).
The `oeedger8r` is built by the CMake target `oeedger8r_target`.

The `oeedger8r` tool is written in OCaml, and builds using
[esy](https://esy.sh/). This is a tool that provides OCaml package management
and reproducible build environments. Instead of installing the native OCaml
tools, `esy` parses the `package.json` file to download and install the exact
OCaml dependencies (including the OCaml compilers and tools, and the `dune`
build system). Running just the command `esy` is equivalent to `esy install &&
esy build` which installs the packages and kicks off the `dune` build, in the
correct environment (this is similar to tools like `pyenv`), and in a
cross-platform manner.

For more information on using writing EDL files and using this tool, please see
[Edger8r Getting Started](../../docs/GettingStartedDocs/Edger8rGettingStarted.md).

To learn how to incorporate `oeedger8r` when using the CMake Package, please
read [CMake Package](../../cmake/sdk_cmake_targets_readme.md).

Developer Notes
---------------

### Changes to Intel's Edger8r code

Intel's Edger8r code exists in the `intel` folder. The following minimal changes
have been made (note that these may be out of date):

1. New `Plugin.ml` file that contains two dependency injection points
   **available** and **gen_edge_routines**. They indicate whether a plugin is
   available or not, and the edge routines generation function installed by the
   plugin. Currently, to avoid distribution challenges, the plugin is compiled
   together with the main edger8r program.

2. Changes to `CodeGen.ml`'s `gen_enclave_code` to check and use a plugin if it exists:
```ocaml
if Plugin.available() then
Plugin.gen_edge_routines ec ep
else (
(if ep.gen_untrusted then (gen_untrusted_header ec; if not ep.header_only then gen_untrusted_source ec));
(if ep.gen_trusted then (gen_trusted_header ec; if not ep.header_only then gen_trusted_source ec))
```

3. Definition of `enclave_content` record type in `Ast.ml` to avoid cyclic
   dependency. The plugin uses `enclave_content` and `edger8r_params` record
   types in addition to the abstract syntax tree types defined in `Ast.ml`. If
   `enclave_content` is defined only in `CodeGen.ml`, then it would lead to a
   cyclic dependency between `CodeGen.ml` and `Plugin.ml`. This is solved by
   defining the `enclave_content` record in `Ast.ml` and redefining it as an
   equivalent type in `CodeGen.ml`.

### Edge Routine Emitter

The edge routine emitter for Open Enclave is implemented in `Emitter.ml`. It
generates code for all the test EDL files. There is also a new `main.ml` which
acts are the program entry point, which we would like remove in favor of an
improved plugin model as it is a copy of Intel's code.

### Best Practices

We use [ocamlformat](https://github.com/ocaml-ppx/ocamlformat) to format our
code (such as `Emitter.ml`, but not Intel's code). It is the final say in
formatting. This should be setup to run automatically in one's editor, as it has
not yet been setup in CI.

We follow [OCamlverse Best Practices](https://ocamlverse.github.io/content/best_practices.html)
(which includes using `ocamlformat`).

For comments, we are in the process of converting to
[OCamldoc](https://ocamlverse.github.io/content/documentation_guidelines.html)
style, which uses `(** [pre-formatted] ... *)` and can later be exported and
rendered.
