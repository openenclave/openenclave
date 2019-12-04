(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

val generate_args : Intel.Ast.enclave_content -> string list

val generate_trusted : Intel.Ast.enclave_content -> string list

val generate_untrusted : Intel.Ast.enclave_content -> string list
