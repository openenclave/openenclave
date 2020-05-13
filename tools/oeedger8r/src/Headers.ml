(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

open Intel.Ast
open Common
open Printf

(** ----- Begin code borrowed and tweaked from {!CodeGen.ml}. ----- *)

(** [conv_array_to_ptr] is used to convert Array form into Pointer form.
    {[
      int array[10][20] => [count = 200] int* array
    ]}

    This function is called when generating proxy/bridge code and the
    marshalling structure. *)
let conv_array_to_ptr (pd : pdecl) : pdecl =
  let pt, declr = pd in
  let get_count_attr ilist =
    (* XXX: assume the size of each dimension will be > 0. *)
    ANumber (List.fold_left (fun acc i -> acc * i) 1 ilist)
  in
  match pt with
  | PTVal _ -> (pt, declr)
  | PTPtr (aty, pa) ->
      if is_array declr then
        let tmp_declr = { declr with array_dims = [] } in
        let tmp_aty = Ptr aty in
        let tmp_cnt = get_count_attr declr.array_dims in
        let tmp_pa =
          { pa with pa_size = { empty_ptr_size with ps_count = Some tmp_cnt } }
        in
        (PTPtr (tmp_aty, tmp_pa), tmp_declr)
      else (pt, declr)

(** ----- End code borrowed and tweaked from {!CodeGen.ml} ----- *)

(** Generate the prototype for a given function. *)
let get_function_prototype (fd : func_decl) =
  let plist_str =
    let args = List.map get_parameter_str fd.plist in
    match args with
    | [] -> "void"
    | [ arg ] -> arg
    | _ -> "\n    " ^ String.concat ",\n    " args
  in
  sprintf "%s %s(%s)" (get_tystr fd.rtype) fd.fname plist_str

(** Emit [struct], [union], or [enum]. *)
let get_composite_type =
  let get_struct (s : struct_def) =
    [
      "#ifndef EDGER8R_STRUCT_" ^ String.uppercase_ascii s.sname;
      "#define EDGER8R_STRUCT_" ^ String.uppercase s.sname;
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
      "#endif";
      "";
    ]
  in
  let get_union (u : union_def) =
    [
      "#ifndef EDGER8R_UNION_" ^ String.uppercase u.uname;
      "#define EDGER8R_UNION_" ^ String.uppercase u.uname;
      "typedef union " ^ u.uname;
      "{";
      String.concat "\n"
        (List.map
           (fun (atype, decl) ->
             sprintf "    %s %s%s;" (get_tystr atype) decl.identifier
               (get_array_dims decl.array_dims))
           u.umlist);
      "} " ^ u.uname ^ ";";
      "#endif";
      "";
    ]
  in
  let get_enum (e : enum_def) =
    [
      "#ifndef EDGER8R_ENUM_" ^ String.uppercase e.enname;
      "#define EDGER8R_ENUM_" ^ String.uppercase e.enname;
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
      "#endif";
      "";
    ]
  in
  function
  | StructDef s -> get_struct s
  | UnionDef u -> get_union u
  | EnumDef e -> get_enum e

let get_marshal_struct (fd : func_decl) (errno : bool) =
  let get_member_decl (ptype, decl) =
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
      else get_member_decl (PTVal fd.rtype, retval_decl) );
      (if errno then [ "int _ocall_errno;" ] else []);
      flatten_map get_member_decl (List.map conv_array_to_ptr fd.plist);
    ]
    |> List.flatten
  in
  [
    "#ifndef EDGER8R_STRUCT_" ^ String.uppercase_ascii struct_name;
    "#define EDGER8R_STRUCT_" ^ String.uppercase_ascii struct_name;
    "typedef struct _" ^ struct_name;
    "{";
    "    " ^ String.concat "\n    " members;
    "} " ^ struct_name ^ ";";
    "#endif";
    "";
  ]

(* Generate [args.h] which contains [struct]s for ecalls and ocalls *)
let generate_args (ec : enclave_content) =
  let guard_macro =
    "EDGER8R_" ^ String.uppercase ec.enclave_name ^ "_ARGS_H"
  in
  let user_includes =
    let includes = ec.include_list in
    if includes <> [] then List.map (sprintf "#include \"%s\"") includes
    else [ "/* There were no user includes. */" ]
  in
  let user_types =
    let cts = ec.comp_defs in
    if cts <> [] then flatten_map get_composite_type cts
    else [ "/* There were no user defined types. */"; "" ]
  in
  [
    "#ifndef " ^ guard_macro;
    "#define " ^ guard_macro;
    "";
    "#include <openenclave/bits/result.h>";
    "";
    "/**** User includes. ****/";
    String.concat "\n" user_includes;
    "";
    "/**** User defined types in EDL. ****/";
    String.concat "\n" user_types;
    "#endif // " ^ guard_macro;
    "";
  ]

(* Includes are emitted in [args.h]. Imported functions have already
   been brought into function lists. *)
let generate_trusted (ec : enclave_content) =
  let guard = "EDGER8R_" ^ String.uppercase ec.file_shortnm ^ "_T_H" in
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  let trusted_function_ids =
    [
      "enum";
      "{";
      String.concat "\n"
        (List.mapi
           (fun i f ->
             sprintf "    %s = %d,"
               (get_function_id ec.enclave_name f.tf_fdecl)
               i)
           tfs);
      "    " ^ ec.enclave_name ^ "_fcn_id_trusted_call_id_max = OE_ENUM_MAX";
      "};";
    ]
  in
  let untrusted_function_ids =
    [
      "enum";
      "{";
      String.concat "\n"
        (List.mapi
           (fun i f ->
             sprintf "    %s = %d,"
               (get_function_id ec.enclave_name f.uf_fdecl)
               i)
           ufs);
      "    " ^ ec.enclave_name ^ "_fcn_id_untrusted_call_max = OE_ENUM_MAX";
      "};";
    ]
  in
  let ecall_marshal_structs =
    if tfs <> [] then
      flatten_map (fun tf -> get_marshal_struct tf.tf_fdecl false) tfs
    else [ "/* There were no ecalls. */"; "" ]
  in
  let ocall_marshal_structs =
    if ufs <> [] then
      flatten_map
        (fun uf -> get_marshal_struct uf.uf_fdecl uf.uf_propagate_errno)
        ufs
    else [ "/* There were no ocalls. */"; "" ]
  in
  let tfunc_prototypes =
    if tfs <> [] then
      List.map (fun f -> sprintf "%s;" (get_function_prototype f.tf_fdecl)) tfs
    else [ "/* There were no ecalls. */" ]
  in
  let ufunc_wrapper_prototypes =
    if ufs <> [] then
      List.map
        (fun f -> sprintf "%s;" (get_wrapper_prototype f.uf_fdecl false))
        ufs
    else [ "/* There were no ocalls. */" ]
  in
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
    "/**** Trusted function IDs ****/";
    String.concat "\n" trusted_function_ids;
    "";
    "/**** ECALL marshalling structs. ****/";
    String.concat "\n" ecall_marshal_structs;
    "/**** ECALL prototypes. ****/";
    String.concat "\n\n" tfunc_prototypes;
    "";
    "/**** Untrusted function IDs. ****/";
    String.concat "\n" untrusted_function_ids;
    "";
    "/**** OCALL marshalling structs. ****/";
    String.concat "\n" ocall_marshal_structs;
    "/**** OCALL prototypes. ****/";
    String.concat "\n\n" ufunc_wrapper_prototypes;
    "";
    "OE_EXTERNC_END";
    "";
    "#endif // " ^ guard;
    "";
  ]

let generate_untrusted (ec : enclave_content) =
  let guard = "EDGER8R_" ^ String.uppercase ec.file_shortnm ^ "_U_H" in
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  let trusted_function_ids =
    [
      "enum";
      "{";
      String.concat "\n"
        (List.mapi
           (fun i f ->
             sprintf "    %s = %d,"
               (get_function_id ec.enclave_name f.tf_fdecl)
               i)
           tfs);
      "    " ^ ec.enclave_name ^ "_fcn_id_trusted_call_id_max = OE_ENUM_MAX";
      "};";
    ]
  in
  let untrusted_function_ids =
    [
      "enum";
      "{";
      String.concat "\n"
        (List.mapi
           (fun i f ->
             sprintf "    %s = %d,"
               (get_function_id ec.enclave_name f.uf_fdecl)
               i)
           ufs);
      "    " ^ ec.enclave_name ^ "_fcn_id_untrusted_call_max = OE_ENUM_MAX";
      "};";
    ]
  in
  let ecall_marshal_structs =
    if tfs <> [] then
      flatten_map (fun tf -> get_marshal_struct tf.tf_fdecl false) tfs
    else [ "/* There were no ecalls. */"; "" ]
  in
  let ocall_marshal_structs =
    if ufs <> [] then
      flatten_map
        (fun uf -> get_marshal_struct uf.uf_fdecl uf.uf_propagate_errno)
        ufs
    else [ "/* There were no ocalls. */"; "" ]
  in
  let tfunc_wrapper_prototypes =
    if tfs <> [] then
      List.map (fun f -> get_wrapper_prototype f.tf_fdecl true ^ ";") tfs
    else [ "/* There were no ecalls. */" ]
  in
  let ufunc_prototypes =
    if ufs <> [] then
      List.map (fun f -> get_function_prototype f.uf_fdecl ^ ";") ufs
    else [ "/* There were no ocalls. */" ]
  in
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
    "/**** Trusted function IDs ****/";
    String.concat "\n" trusted_function_ids;
    "";
    "/**** ECALL marshalling structs. ****/";
    String.concat "\n" ecall_marshal_structs;
    "/**** ECALL prototypes. ****/";
    String.concat "\n\n" tfunc_wrapper_prototypes;
    "";
    "/**** Untrusted function IDs. ****/";
    String.concat "\n" untrusted_function_ids;
    "";
    "/**** OCALL marshalling structs. ****/";
    String.concat "\n" ocall_marshal_structs;
    "/**** OCALL prototypes. ****/";
    String.concat "\n\n" ufunc_prototypes;
    "";
    "OE_EXTERNC_END";
    "";
    "#endif // " ^ guard;
    "";
  ]
