(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

val generate_trusted :
  Intel.Ast.enclave_content -> Intel.Util.edger8r_params -> string list

val generate_untrusted :
  Intel.Ast.enclave_content -> Intel.Util.edger8r_params -> string list
