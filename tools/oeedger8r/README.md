# Open Enclave Edger8r POC

This folder contains Proof Of Concept of adapting Intel Edger8r to generate Open Enclave edge routines.

---
## Building and Running

### Build

`$ make`

This creates **dist/oe_edger8r**.

### Run

`$ cd test`

`$ ../dist/oe_edger8r array.edl`

This should generate _t.h, _t.c, _u.h, _u.c and _args.h files.

### Clean
`$ make clean`

---
## Documentation

### Changes to Intel's Edger8r code
Intel's Edger8r code exists in the intel folder. The following minimal changes have been made:

1. New Plugin.ml file that contains two dependency injection points **available** and **gen_edge_routines**.
   They indicate whether a plugin is available or not, and the edge routines generation function installed by the plugin.
   Currently, to avoid distribution challenges, the plugin is compiled together with the main edger8r program.
2. Changes to CodeGen.ml's gen_enclave_code to check and use a plugin if it exists:
    ```ocaml
        if Plugin.available() then
        Plugin.gen_edge_routines ec ep
        else (      
        (if ep.gen_untrusted then (gen_untrusted_header ec; if not ep.header_only then gen_untrusted_source ec));
        (if ep.gen_trusted then (gen_trusted_header ec; if not ep.header_only then gen_trusted_source ec))    
    ```
3. Definition of enclave_content record type in Ast.ml to avoid cyclic dependency. The plugin uses enclave_content and 
   edger8r_params record types in addition to the abstract syntax tree types defined in Ast.ml.
   If enclave_content is defined only in CodeGen.ml, then it would lead to a cyclic dependency between CodeGen.ml and Plugin.ml.
   This is solved by defining the enclave_content record in Ast.ml and redefining it as an equivalent type in CodeGen.ml.

### Open Enclave Emitter

Edge routine emitter for Open Enclave is implemented in Emitter.ml. It generates code for all the test .edl files.
It is work in progress. There is also a new main.ml which acts are the program entry point. I would like to somehow get rid of that.

#### Best Practices

We follow [OCamlverse Best Practices](https://ocamlverse.github.io/content/best_practices.html).

We use [ocp-indent](https://github.com/OCamlPro/ocp-indent) to indent our code
(but not the code imported from Intel).
This can be run manually or with an editor such as
[Emacs](https://github.com/ocaml/tuareg/blob/master/dot-emacs.el).

For comments, we are in the process of converting to
[OCamldoc](https://ocamlverse.github.io/content/documentation_guidelines.html) style,
which uses `(** [pre-formatted] ... *)` and can later be exported and rendered.
