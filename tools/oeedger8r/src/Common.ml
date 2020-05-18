(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

open Intel.Ast
open Printf

(** ----- Begin code borrowed and tweaked from {!CodeGen.ml}. ----- *)

let is_foreign_array = function
  | PTVal _ -> false
  | PTPtr (t, a) -> ( match t with Foreign _ -> a.pa_isary | _ -> false )

(** Get the array declaration from a list of array dimensions. Empty
    [ns] indicates the corresponding declarator is a simple identifier.
    Element of value -1 means that user does not specify the dimension
    size. *)
let get_array_dims (ns : int list) =
  let get_dim n = if n = -1 then "[]" else sprintf "[%d]" n in
  String.concat "" (List.map get_dim ns)

let get_typed_declr_str (ty : atype) (declr : declarator) =
  let tystr = get_tystr ty in
  let dmstr = get_array_dims declr.array_dims in
  sprintf "%s %s%s" tystr declr.identifier dmstr

(** Check whether given parameter [pt] is [const] specified. *)
let is_const_ptr (pt : parameter_type) =
  let aty = get_param_atype pt in
  match pt with
  | PTVal _ -> false
  | PTPtr (_, pa) -> (
      if not pa.pa_rdonly then false
      else match aty with Foreign _ -> false | _ -> true )

(** Generate parameter [p] representation. *)
let get_parameter_str (p : pdecl) =
  let pt, (declr : declarator) = p in
  let aty = get_param_atype pt in
  let str = get_typed_declr_str aty declr in
  if is_const_ptr pt then "const " ^ str else str

(** ----- End code borrowed and tweaked from {!CodeGen.ml} ----- *)

(* Helper to flatten and map at the same time. *)
let flatten_map f l = List.flatten (List.map f l)

let flatten_map2 f l m = List.flatten (List.map2 f l m)

let is_in_ptr = function
  | PTVal _ -> false
  | PTPtr (_, a) -> a.pa_chkptr && a.pa_direction = PtrIn

let is_out_ptr = function
  | PTVal _ -> false
  | PTPtr (_, a) -> a.pa_chkptr && a.pa_direction = PtrOut

let is_inout_ptr = function
  | PTVal _ -> false
  | PTPtr (_, a) -> a.pa_chkptr && a.pa_direction = PtrInOut

let is_in_or_inout_ptr (p, _) = is_in_ptr p || is_inout_ptr p

let is_out_or_inout_ptr (p, _) = is_out_ptr p || is_inout_ptr p

let is_str_ptr = function PTVal _ -> false | PTPtr (_, a) -> a.pa_isstr

let is_wstr_ptr = function PTVal _ -> false | PTPtr (_, a) -> a.pa_iswstr

let is_str_or_wstr_ptr (p, _) = is_str_ptr p || is_wstr_ptr p

(* This tests if the member has a non-empty size attribute,
   implying that it should be marshalled. *)
let is_marshalled_ptr = function
  | PTPtr (_, attr) -> attr.pa_size <> empty_ptr_size
  | PTVal _ -> false

(** Generate the wrapper prototype for a given function. Optionally
    add an [oe_enclave_t*] first parameter. *)
let get_wrapper_prototype (fd : func_decl) (is_ecall : bool) =
  let plist_str =
    let args =
      [
        (if is_ecall then [ "oe_enclave_t* enclave" ] else []);
        ( match fd.rtype with
        | Void -> []
        | _ -> [ get_tystr fd.rtype ^ "* _retval" ] );
        List.map get_parameter_str fd.plist;
      ]
      |> List.flatten
    in
    match args with
    | [ arg ] -> arg
    | _ -> "\n    " ^ String.concat ",\n    " args
  in
  sprintf "oe_result_t %s(%s)" fd.fname plist_str

let get_function_id (enclave_name : string) (f : func_decl) =
  enclave_name ^ "_fcn_id_" ^ f.fname
