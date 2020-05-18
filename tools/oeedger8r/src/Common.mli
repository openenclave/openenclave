(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

val is_foreign_array : Intel.Ast.parameter_type -> bool

val get_array_dims : int list -> string

val get_parameter_str : Intel.Ast.pdecl -> string

val flatten_map : ('a -> 'b list) -> 'a list -> 'b list

val flatten_map2 : ('a -> 'b -> 'c list) -> 'a list -> 'b list -> 'c list

val is_in_ptr : Intel.Ast.parameter_type -> bool

val is_out_ptr : Intel.Ast.parameter_type -> bool

val is_inout_ptr : Intel.Ast.parameter_type -> bool

val is_in_or_inout_ptr : Intel.Ast.parameter_type * 'a -> bool

val is_out_or_inout_ptr : Intel.Ast.parameter_type * 'a -> bool

val is_str_ptr : Intel.Ast.parameter_type -> bool

val is_wstr_ptr : Intel.Ast.parameter_type -> bool

val is_str_or_wstr_ptr : Intel.Ast.parameter_type * 'a -> bool

val is_marshalled_ptr : Intel.Ast.parameter_type -> bool

val get_wrapper_prototype : Intel.Ast.func_decl -> bool -> string

val get_function_id : string -> Intel.Ast.func_decl -> string
