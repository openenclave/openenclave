(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

open Intel.Ast
open Common
open Printf

(** Generate the prototype for a given function. *)
let oe_gen_prototype (fd : func_decl) =
  let plist_str =
    let args = List.map gen_parm_str fd.plist in
    match args with
    | [] -> "void"
    | [ arg ] -> arg
    | _ -> "\n    " ^ String.concat ",\n    " args
  in
  sprintf "%s %s(%s)" (get_tystr fd.rtype) fd.fname plist_str

(** Emit [struct], [union], or [enum]. *)
let emit_composite_type =
  let emit_struct (s : struct_def) =
    [
      "typedef struct " ^ s.sname;
      "{";
      String.concat "\n"
        (List.map
           (fun (ptype, decl) ->
             sprintf "    %s %s%s;"
               (get_tystr (get_param_atype ptype))
               decl.identifier
               (get_array_dims decl.array_dims))
           s.smlist);
      "} " ^ s.sname ^ ";";
      "";
    ]
  in
  let emit_union (u : union_def) =
    [
      "typedef union " ^ u.uname;
      "{";
      String.concat "\n"
        (List.map
           (fun (atype, decl) ->
             sprintf "    %s %s%s;" (get_tystr atype) decl.identifier
               (get_array_dims decl.array_dims))
           u.umlist);
      "} " ^ u.uname ^ ";";
      "";
    ]
  in
  let emit_enum (e : enum_def) =
    [
      "typedef enum " ^ e.enname;
      "{";
      String.concat ",\n"
        (List.map
           (fun (name, value) ->
             sprintf "    %s%s" name
               ( match value with
               | EnumVal (AString s) -> " = " ^ s
               | EnumVal (ANumber n) -> " = " ^ string_of_int n
               | EnumValNone -> "" ))
           e.enbody);
      "} " ^ e.enname ^ ";";
      "";
    ]
  in
  function
  | StructDef s -> emit_struct s
  | UnionDef u -> emit_union u
  | EnumDef e -> emit_enum e

(* Generate [args.h] which contains [struct]s for ecalls and ocalls *)
let generate_args (ec : enclave_content) =
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  (* Emit IDs in enum for trusted functions. *)
  let emit_trusted_function_ids =
    [
      "enum";
      "{";
      String.concat "\n"
        (List.mapi
           (fun i f -> sprintf "    %s = %d," (get_function_id ec f.tf_fdecl) i)
           tfs);
      "    " ^ ec.enclave_name ^ "_fcn_id_trusted_call_id_max = OE_ENUM_MAX";
      "};";
    ]
  in
  (* Emit IDs in enum for untrusted functions. *)
  let emit_untrusted_function_ids =
    [
      "enum";
      "{";
      String.concat "\n"
        (List.mapi
           (fun i f -> sprintf "    %s = %d," (get_function_id ec f.uf_fdecl) i)
           ufs);
      "    " ^ ec.enclave_name ^ "_fcn_id_untrusted_call_max = OE_ENUM_MAX";
      "};";
    ]
  in
  let oe_gen_marshal_struct (fd : func_decl) (errno : bool) =
    let gen_member_decl (ptype, decl) =
      let aty = get_param_atype ptype in
      let tystr = get_tystr aty in
      let tystr =
        if is_foreign_array ptype then
          sprintf "/* foreign array of type %s */ void*" tystr
        else tystr
      in
      let need_strlen =
        is_str_or_wstr_ptr (ptype, decl) && is_in_or_inout_ptr (ptype, decl)
      in
      let id = decl.identifier in
      [
        [ tystr ^ " " ^ id ^ ";" ];
        (if need_strlen then [ sprintf "size_t %s_len;" id ] else []);
      ]
      |> List.flatten
    in
    let struct_name = fd.fname ^ "_args_t" in
    let retval_decl = { identifier = "_retval"; array_dims = [] } in
    let members =
      [
        [ "oe_result_t _result;" ];
        ( if fd.rtype = Void then []
        else gen_member_decl (PTVal fd.rtype, retval_decl) );
        (if errno then [ "int _ocall_errno;" ] else []);
        flatten_map gen_member_decl (List.map conv_array_to_ptr fd.plist);
      ]
      |> List.flatten
    in
    [
      "typedef struct _" ^ struct_name;
      "{";
      "    " ^ String.concat "\n    " members;
      "} " ^ struct_name ^ ";";
      "";
    ]
  in
  let oe_gen_user_includes (includes : string list) =
    if includes <> [] then List.map (sprintf "#include \"%s\"") includes
    else [ "/* There were no user includes. */" ]
  in
  let oe_gen_user_types (cts : composite_type list) =
    if cts <> [] then flatten_map emit_composite_type cts
    else [ "/* There were no user defined types. */"; "" ]
  in
  let oe_gen_ecall_marshal_structs =
    if tfs <> [] then
      flatten_map (fun tf -> oe_gen_marshal_struct tf.tf_fdecl false) tfs
    else [ "/* There were no ecalls. */"; "" ]
  in
  let oe_gen_ocall_marshal_structs =
    if ufs <> [] then
      flatten_map
        (fun uf -> oe_gen_marshal_struct uf.uf_fdecl uf.uf_propagate_errno)
        ufs
    else [ "/* There were no ocalls. */"; "" ]
  in
  let with_errno = List.exists (fun uf -> uf.uf_propagate_errno) ufs in
  let guard_macro =
    "EDGER8R_" ^ String.uppercase_ascii ec.enclave_name ^ "_ARGS_H"
  in
  [
    "#ifndef " ^ guard_macro;
    "#define " ^ guard_macro;
    "";
    "#include <stdint.h>";
    "#include <stdlib.h> /* for wchar_t */";
    "";
    (let s = "#include <errno.h>" in
     if with_errno then s
     else sprintf "/* %s - Errno propagation not enabled so not included. */" s);
    "";
    "#include <openenclave/bits/result.h>";
    "";
    "/**** User includes. ****/";
    String.concat "\n" (oe_gen_user_includes ec.include_list);
    "";
    "/**** User defined types in EDL. ****/";
    String.concat "\n" (oe_gen_user_types ec.comp_defs);
    "/**** ECALL marshalling structs. ****/";
    String.concat "\n" oe_gen_ecall_marshal_structs;
    "/**** OCALL marshalling structs. ****/";
    String.concat "\n" oe_gen_ocall_marshal_structs;
    "/**** Trusted function IDs ****/";
    String.concat "\n" emit_trusted_function_ids;
    "";
    "/**** Untrusted function IDs. ****/";
    String.concat "\n" emit_untrusted_function_ids;
    "";
    "#endif // " ^ guard_macro;
    "";
  ]

(* Includes are emitted in [args.h]. Imported functions have already
     been brought into function lists. *)
let generate_trusted (ec : enclave_content) (ep : Intel.Util.edger8r_params) =
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  let oe_gen_tfunc_prototypes =
    if tfs <> [] then
      List.map (fun f -> sprintf "%s;" (oe_gen_prototype f.tf_fdecl)) tfs
    else [ "/* There were no ecalls. */" ]
  in
  let oe_gen_ufunc_wrapper_prototypes =
    if ufs <> [] then
      List.map
        (fun f -> sprintf "%s;" (oe_gen_wrapper_prototype f.uf_fdecl false))
        ufs
    else [ "/* There were no ocalls. */" ]
  in
  let guard = "EDGER8R_" ^ String.uppercase_ascii ec.file_shortnm ^ "_T_H" in
  [
    "#ifndef " ^ guard;
    "#define " ^ guard;
    "";
    "#include <openenclave/enclave.h>";
    "";
    sprintf "#include \"%s_args.h\"" ec.file_shortnm;
    "";
    "OE_EXTERNC_BEGIN";
    "";
    "/**** ECALL prototypes. ****/";
    String.concat "\n\n" oe_gen_tfunc_prototypes;
    "";
    "/**** OCALL prototypes. ****/";
    String.concat "\n\n" oe_gen_ufunc_wrapper_prototypes;
    "";
    "OE_EXTERNC_END";
    "";
    "#endif // " ^ guard;
    "";
  ]

let generate_untrusted (ec : enclave_content) (ep : Intel.Util.edger8r_params) =
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  let oe_gen_tfunc_wrapper_prototypes =
    if tfs <> [] then
      List.map (fun f -> oe_gen_wrapper_prototype f.tf_fdecl true ^ ";") tfs
    else [ "/* There were no ecalls. */" ]
  in
  let oe_gen_ufunc_prototypes =
    if ufs <> [] then List.map (fun f -> oe_gen_prototype f.uf_fdecl ^ ";") ufs
    else [ "/* There were no ocalls. */" ]
  in
  let guard = "EDGER8R_" ^ String.uppercase_ascii ec.file_shortnm ^ "_U_H" in
  [
    "#ifndef " ^ guard;
    "#define " ^ guard;
    "";
    "#include <openenclave/host.h>";
    "";
    sprintf "#include \"%s_args.h\"" ec.file_shortnm;
    "";
    "OE_EXTERNC_BEGIN";
    "";
    sprintf "oe_result_t oe_create_%s_enclave(" ec.enclave_name;
    "    const char* path,";
    "    oe_enclave_type_t type,";
    "    uint32_t flags,";
    "    const oe_enclave_setting_t* settings,";
    "    uint32_t setting_count,";
    "    oe_enclave_t** enclave);";
    "";
    "/**** ECALL prototypes. ****/";
    String.concat "\n\n" oe_gen_tfunc_wrapper_prototypes;
    "";
    "/**** OCALL prototypes. ****/";
    String.concat "\n\n" oe_gen_ufunc_prototypes;
    "";
    "OE_EXTERNC_END";
    "";
    "#endif // " ^ guard;
    "";
  ]
