(* Copyright (c) Open Enclave SDK contributors.
   Licensed under the MIT License. *)

open Intel.Ast
open Common
open Printf

(** Given [name], return the corresponding [StructDef], or [None]. *)
let get_struct_by_name (cts : composite_type list) (name : string) =
  (* [cts] is a list of all composite types, but we're only
     interested in the structs, so we filter out the rest and unwrap
     them from [composite_type]. *)
  let structs = filter_map (function StructDef s -> Some s | _ -> None) cts in
  List.find_opt (fun s -> s.sname = name) structs

(** We need to check [Ptr]s for [Foreign] or [Struct] types, then
    check those against the user's [Struct]s, and then check if any
    members should be deep copied. What we return is the list of
    members of the [Struct] which should be deep-copied, otherwise we
    return an empty list.

    NOTE: This is a higher-order function that is mean to have its
    first two arguments partially applied, and then used repeatedly. *)
let get_deepcopy_function (enabled : bool) (cts : composite_type list)
    (a : atype) =
  let should_deepcopy_a = function
    | Ptr (Struct n) | Ptr (Foreign n) -> get_struct_by_name cts n
    | _ -> None
  in
  if enabled then
    match should_deepcopy_a a with
    | Some s -> List.filter (fun (p, _) -> is_marshalled_ptr p) s.smlist
    | None -> []
  else []

let gen_c_for level count body =
  if count = "1" then body
  else
    let i = sprintf "_i_%i" level in
    [
      [ sprintf "for (size_t %s = 0; %s < %s; %s++)" i i count i ];
      [ "{" ];
      List.map (( ^ ) "    ") body;
      [ "}" ];
    ]
    |> List.flatten

let gen_c_deref level i = if i = "1" then "->" else sprintf "[_i_%i]." level

let attr_value_to_string argstruct = function
  | None -> None
  | Some (ANumber n) -> Some (string_of_int n)
  | Some (AString s) -> Some (argstruct ^ s)

(** For a list of args and current count, get the corresponding
   argstruct variable name. The prefix is usually, but not always,
   ["_args."].*)
let get_argstruct prefix args count =
  match args with
  | [] -> prefix
  | hd :: _ -> prefix ^ hd ^ gen_c_deref (List.length args) count

let get_type_expr ptype =
  (* Get the base type of the parameter. That is, yield its [atype],
     unless it is a pointer, in which case decompose and yield the
     [atype] the pointer points to. *)
  let param_atype =
    let a = get_param_atype ptype in
    match a with Ptr p -> p | _ -> a
  in
  let tystr = get_tystr param_atype in
  match ptype with
  | PTPtr (_, ptr_attr) when ptr_attr.pa_isptr -> sprintf "*(%s)0" tystr
  | _ -> tystr

(** For a parameter, get its size expression. *)
let _get_param_size (ptype, decl, argstruct) =
  let type_expr = get_type_expr ptype in
  let get_ptr_or_decl_size (p : ptr_size) =
    let size = attr_value_to_string argstruct p.ps_size
    and count = attr_value_to_string argstruct p.ps_count in
    match (size, count) with
    | Some s, None -> s
    (* TODO: Check that c actually fits in size_t. Also check for overflow,
     * similar to oe_add_size *)
    | None, Some c -> sprintf "((size_t)%s * sizeof(%s))" c type_expr
    (* TODO: Check that this is an even multiple of the size of type. *)
    | Some s, Some c -> sprintf "(%s * %s)" s c
    | None, None ->
        sprintf "sizeof(%s%s)" type_expr (get_array_dims decl.array_dims)
  in
  match ptype with
  | PTPtr (_, ptr_attr) ->
      if ptr_attr.pa_isstr then
        Some (argstruct ^ decl.identifier ^ "_len * sizeof(char)")
      else if ptr_attr.pa_iswstr then
        Some (argstruct ^ decl.identifier ^ "_len * sizeof(wchar_t)")
      else if ptr_attr.pa_chkptr then
        Some (get_ptr_or_decl_size ptr_attr.pa_size)
      else None
  (* Values have no marshalling size. *)
  | _ -> None

let get_param_size (ptype, decl, argstruct) =
  match _get_param_size (ptype, decl, argstruct) with
  | Some size -> size
  | None -> Intel.Util.failwithf "Error: No size for " ^ decl.identifier

(** For a parameter, get its count expression. *)
let _get_param_count (ptype, decl, argstruct) =
  let type_expr = get_type_expr ptype in
  let get_ptr_or_decl_count (p : ptr_size) =
    let size = attr_value_to_string argstruct p.ps_size
    and count = attr_value_to_string argstruct p.ps_count in
    match (size, count) with
    (* TODO: Check that these are even multiples of the size of type. *)
    | Some s, None -> sprintf "(%s / sizeof(%s))" s type_expr
    | None, Some c -> c
    | Some s, Some c -> sprintf "((%s * %s) / sizeof(%s))" s c type_expr
    | None, None ->
        let dims = List.map string_of_int decl.array_dims in
        String.concat " * " dims
  in
  match ptype with
  | PTPtr (_, ptr_attr) ->
      (* The count of a string is its length. *)
      if ptr_attr.pa_isstr || ptr_attr.pa_iswstr then
        (* TODO: Double-check that this length includes the
           null-terminator. *)
        Some (argstruct ^ decl.identifier ^ "_len")
      else if ptr_attr.pa_chkptr then
        Some (get_ptr_or_decl_count ptr_attr.pa_size)
        (* TODO: Should be able to return [Some "1"] for plain
           pointers and values. *)
      else None
  | PTVal _ -> None

let get_param_count (ptype, decl, argstruct) =
  match _get_param_count (ptype, decl, argstruct) with
  | Some count -> count
  | None -> Intel.Util.failwithf "Error: No count for " ^ decl.identifier

(** Generate a cast expression for a pointer argument. Pointer
    arguments need to be cast to their root type, since the marshalling
    struct has the root pointer. For example:
    {[
      int a[10][20]
    ]}
    needs to be cast to [int *].

    NOTE: Foreign arrays are marshalled as [void *], but foreign pointers
    are marshalled as-is. *)
let get_cast_to_mem_expr (ptype, decl) (parens : bool) =
  match ptype with
  | PTVal _ -> ""
  | PTPtr (t, _) ->
      let tystr = get_tystr t in
      if is_array decl then
        let s = tystr ^ "*" in
        if parens then sprintf "(%s)" s else s
      else if is_foreign_array ptype then
        let s = if parens then "(void*)" else "void*" in
        sprintf "/* foreign array of type %s */ %s" tystr s
      else if parens then sprintf "(%s)" tystr
      else tystr

(** Recursively generates [if (a && a->b) OE_SET_PTR(a->b->c);]
    statements. *)
let rec get_ptr_setter get_deepcopy args count setter (ptype, decl) =
  let argstruct = get_argstruct "pargs_in->" args count in
  let size = get_param_size (ptype, decl, argstruct) in
  let arg =
    match args with
    | [] -> decl.identifier
    | hd :: _ -> hd ^ gen_c_deref (List.length args) count ^ decl.identifier
  in
  let tystr = get_cast_to_mem_expr (ptype, decl) false in
  gen_c_for (List.length args) count
    ( [
        (* NOTE: This makes the embedded check in the `OE_` macro superfluous. *)
        [
          sprintf "if (pargs_in->%s)"
            (if args = [] then arg
            else ((String.concat " && pargs_in->" (List.rev(args))) ^
              ((if setter = "SET_OUT" then " && !" else " && ") ^
              "pargs_in->" ^ arg)))
        ];
        [ sprintf "    OE_%s_POINTER(%s, %s, %s);" setter arg size tystr ];
        (let param_count = get_param_count (ptype, decl, argstruct) in
         flatten_map
           (get_ptr_setter get_deepcopy (arg :: args) param_count setter)
           (get_deepcopy (get_param_atype ptype)));
      ]
    |> List.flatten )

(** Generates pointer setters for in and in-out pointers. *)
let get_in_ptr_setter get_deepcopy (plist : pdecl list) =
  let params =
    let ptrs = List.filter is_in_or_inout_ptr plist in
    let setters =
      List.map
        (fun (p, _) -> if is_in_ptr p then "SET_IN" else "SET_IN_OUT")
        ptrs
    in
    flatten_map2 (get_ptr_setter get_deepcopy [] "1") setters ptrs
  in
  "    "
  ^ String.concat "\n    "
      [
        "/* Set in and in-out pointers. */";
        ( if params <> [] then String.concat "\n    " params
        else "/* There were no in nor in-out parameters. */" );
      ]

(** Generates pointer setters for out and in-out pointers. *)
let get_out_ptr_setter get_deepcopy (plist : pdecl list) =
  let params =
    let ptrs = List.filter is_out_or_inout_ptr plist in
    let setters =
      List.map
        (fun (p, _) ->
          if is_out_ptr p then "SET_OUT" else "COPY_AND_SET_IN_OUT")
        ptrs
    in
    flatten_map2 (get_ptr_setter get_deepcopy [] "1") setters ptrs
  in
  "    "
  ^ String.concat "\n    "
      [
        "/* Set out and in-out pointers. */";
        "/* In-out parameters are copied to output buffer. */";
        ( if params <> [] then String.concat "\n    " params
        else "/* There were no out nor in-out parameters. */" );
      ]

(** Generates an expression representing the total number of pointers
    we need to save and restore, used as the size for the pointer
    array. *)
let rec get_ptr_count get_deepcopy args count (ptype, decl) =
  let get_multiplication_expr count body =
    (* The first two conditionals check for the multiplicative identity
       and prevent unnecessary expressions from being generated.
       Otherwise we multiply the sum of [body] by [count]. *)
    if count = "1" || body = [] then body
    else if List.length body = 1 && List.hd body = "1" then [ count ]
    else [ count ^ " * (" ^ String.concat " + " body ^ ")" ]
  in
  let id = decl.identifier in
  (* TODO: The use of [gen_c_deref] does not work here as we are not
     within a [gen_c_for] loop when producing the count. Therefore
     arrays of structs which use members for the count of another
     nested parameter are not yet supported. *)
  let argstruct = get_argstruct "" args count in
  let arg =
    match args with
    | [] -> id
    | hd :: _ -> hd ^ gen_c_deref (List.length args) count ^ id
  in
  let param_count = get_param_count (ptype, decl, argstruct) in
  let members = get_deepcopy (get_param_atype ptype) in
  if is_marshalled_ptr ptype then
    (* The base case is a marshalled pointer. We count 1 for every one
       of these, except for the top-level pointers as they are the
       original function arguments, and so do not need to be
       saved/restored.

       For a marshalled pointer, we then need to recurse. If there are
       no members to recurse on, then [members] is the empty list and
       the recursion is a no-op, leaving us back at the base case of
       counting 1. If there are members to recurse on, then we count 1
       plus the current [param_count] times the number of members for
       each nested structure. *)
    (if args <> [] then [ "1" ] else [])
    @ get_multiplication_expr param_count
        (flatten_map
           (get_ptr_count get_deepcopy (arg :: args) param_count)
           members)
  else []

(** Generates the array used to save the original pointers. *)
let get_ptr_array get_deepcopy (plist : pdecl list) =
  let count =
    flatten_map
      (get_ptr_count get_deepcopy [] "1")
      (List.filter is_out_or_inout_ptr plist)
  in
  if count <> [] then
    [
      "size_t _ptrs_index = 0;";
      sprintf "void** _ptrs = oe_malloc(sizeof(void*) * (%s));"
        (String.concat " + " count);
      "if (_ptrs == NULL)";
      "{";
      "    _result = OE_OUT_OF_MEMORY;";
      "    goto done;";
      "}";
    ]
  else [ "/* No pointers to save for deep copy. */" ]

(** Generates expression to reset the index into the pointer array. *)
let get_ptr_index_reset get_deepcopy (plist : pdecl list) =
  let count =
    flatten_map
      (get_ptr_count get_deepcopy [] "1")
      (List.filter is_out_or_inout_ptr plist)
  in
  if count <> [] then "_ptrs_index = 0; /* For deep copy. */"
  else "/* No pointers to restore for deep copy. */"

let get_ptr_free_expr get_deepcopy (plist : pdecl list) =
  let count =
    flatten_map
      (get_ptr_count get_deepcopy [] "1")
      (List.filter is_out_or_inout_ptr plist)
  in
  if count <> [] then [ "if (_ptrs)"; "    free(_ptrs);" ]
  else [ "/* No `_ptrs` to free for deep copy. */" ]

let get_filled_marshal_struct get_deepcopy (fd : func_decl) =
  (* Generate assignment argument to corresponding field in args. This
     is necessary for all arguments, not just copy-as-value, because
     they are used directly by later marshalling code. *)
  let get_assignment_to_args (ptype, decl) =
    let arg = decl.identifier in
    [
      [
        sprintf "_args.%s = %s%s;" arg
          (get_cast_to_mem_expr (ptype, decl) true)
          arg;
      ];
      (* for string parameter fill the len field *)
      ( if is_str_ptr ptype then
        [ sprintf "_args.%s_len = (%s) ? (oe_strlen(%s) + 1) : 0;" arg arg arg ]
      else if is_wstr_ptr ptype then
        [ sprintf "_args.%s_len = (%s) ? (oe_wcslen(%s) + 1) : 0;" arg arg arg ]
      else [] );
    ]
    |> List.flatten
  in
  flatten_map get_assignment_to_args fd.plist
  @
  let rec get_saved_ptrs args count (ptype, decl) =
    let id = decl.identifier in
    let argstruct = get_argstruct "_args." args count in
    let arg =
      match args with
      | [] -> id
      | hd :: _ -> hd ^ gen_c_deref (List.length args) count ^ id
    in
    gen_c_for (List.length args) count
      ( [
          ( if args <> [] then
            [ sprintf "if (%s)" (String.concat " && " (List.rev args)) ]
          else [] );
          ( if args <> [] && is_marshalled_ptr ptype then
            [ "    _ptrs[_ptrs_index++] = (void*)" ^ arg ^ ";" ]
          else [] );
          (let param_count = get_param_count (ptype, decl, argstruct) in
           flatten_map
             (get_saved_ptrs (arg :: args) param_count)
             (get_deepcopy (get_param_atype ptype)));
        ]
      |> List.flatten )
  in
  flatten_map (get_saved_ptrs [] "1") (List.filter is_out_or_inout_ptr fd.plist)

(* Prepare [input_buffer]. *)
let get_input_buffer get_deepcopy (fd : func_decl) (alloc_func : string) =
  let get_buffer_size buffer predicate plist =
    let rec get_add_size_expr args count (ptype, decl) =
      let argstruct = get_argstruct "_args." args count in
      let size = get_param_size (ptype, decl, argstruct) in
      let arg =
        match args with
        | [] -> decl.identifier
        | hd :: _ -> hd ^ gen_c_deref (List.length args) count ^ decl.identifier
      in
      gen_c_for (List.length args) count
        ( [
            [ sprintf "if (%s)" (String.concat " && " (List.rev (arg :: args))) ];
            [ sprintf "    OE_ADD_SIZE(%s, %s);" buffer size ];
            (let param_count = get_param_count (ptype, decl, argstruct) in
             flatten_map
               (get_add_size_expr (arg :: args) param_count)
               (get_deepcopy (get_param_atype ptype)));
          ]
        |> List.flatten )
    in
    let params =
      flatten_map (get_add_size_expr [] "1") (List.filter predicate plist)
    in
    (* Note that the indentation for the first line is applied by the
         parent function. *)
    if params <> [] then String.concat "\n    " params
    else "/* There were no corresponding parameters. */"
  in
  let get_input_buffer_size =
    get_buffer_size "_input_buffer_size" is_in_or_inout_ptr
  in
  let get_output_buffer_size =
    get_buffer_size "_output_buffer_size" is_out_or_inout_ptr
  in
  let get_serialized_buffer_inputs (plist : pdecl list) =
    let rec get_serializer args count (ptype, decl) =
      let argstruct = get_argstruct "_args." args count in
      let size = get_param_size (ptype, decl, argstruct) in
      let arg =
        match args with
        | [] -> decl.identifier
        | hd :: _ -> hd ^ gen_c_deref (List.length args) count ^ decl.identifier
      in
      let tystr = get_cast_to_mem_expr (ptype, decl) false in
      (* These need to be in order and so done together. *)
      gen_c_for (List.length args) count
        ( [
            (* NOTE: This makes the embedded check in the `OE_` macro superfluous. *)
            [
              sprintf "if (%s)" (String.concat " && " (List.rev (arg :: args)));
            ];
            [
              (* NOTE: The [WRITE_IN_OUT] macro is defined to be the
                 [WRITE_IN] macro. *)
              sprintf "    OE_WRITE_%s_PARAM(%s, %s, %s);"
                (if is_in_ptr ptype then "IN" else "IN_OUT")
                arg size tystr;
            ];
            (let param_count = get_param_count (ptype, decl, argstruct) in
             flatten_map
               (get_serializer (arg :: args) param_count)
               (get_deepcopy (get_param_atype ptype)));
          ]
        |> List.flatten )
    in
    let params =
      flatten_map (get_serializer [] "1") (List.filter is_in_or_inout_ptr plist)
    in
    (* Note that the indentation for the first line is applied by the
         parent function. *)
    if params <> [] then String.concat "\n    " params
    else "/* There were no in nor in-out parameters. */"
  in
  [
    "/* Compute input buffer size. Include in and in-out parameters. */";
    sprintf "OE_ADD_SIZE(_input_buffer_size, sizeof(%s_args_t));" fd.fname;
    get_input_buffer_size fd.plist;
    "";
    "/* Compute output buffer size. Include out and in-out parameters. */";
    sprintf "OE_ADD_SIZE(_output_buffer_size, sizeof(%s_args_t));" fd.fname;
    get_output_buffer_size fd.plist;
    "";
    "/* Allocate marshalling buffer. */";
    "_total_buffer_size = _input_buffer_size;";
    "OE_ADD_SIZE(_total_buffer_size, _output_buffer_size);";
    sprintf "_buffer = (uint8_t*)%s(_total_buffer_size);" alloc_func;
    "_input_buffer = _buffer;";
    "_output_buffer = _buffer + _input_buffer_size;";
    "if (_buffer == NULL)";
    "{";
    "    _result = OE_OUT_OF_MEMORY;";
    "    goto done;";
    "}";
    "";
    "/* Serialize buffer inputs (in and in-out parameters). */";
    sprintf "_pargs_in = (%s_args_t*)_input_buffer;" fd.fname;
    "OE_ADD_SIZE(_input_buffer_offset, sizeof(*_pargs_in));";
    get_serialized_buffer_inputs fd.plist;
    "";
    "/* Copy args structure (now filled) to input buffer. */";
    "memcpy(_pargs_in, &_args, sizeof(*_pargs_in));";
  ]

let get_output_buffer get_deepcopy (fd : func_decl) =
  let get_serialized_buffer_outputs (plist : pdecl list) =
    let rec get_serializer args count (ptype, decl) =
      let argstruct = get_argstruct "_args." args count in
      let size = get_param_size (ptype, decl, argstruct) in
      let arg =
        match args with
        | [] -> decl.identifier
        | hd :: _ -> hd ^ gen_c_deref (List.length args) count ^ decl.identifier
      in
      gen_c_for (List.length args) count
        ( [
            ( if is_str_or_wstr_ptr (ptype, decl) then
              [
                sprintf
                  "OE_CHECK_NULL_TERMINATOR%s(_output_buffer + \
                   _output_buffer_offset, _args.%s_len);"
                  (if is_wstr_ptr ptype then "_WIDE" else "")
                  arg;
              ]
            else [] );
            (let s =
               sprintf "OE_READ_%s_PARAM(%s, (size_t)(%s));"
                 (if is_out_ptr ptype then "OUT" else "IN_OUT")
                 arg size
             in
             match args with
             | [] -> [ s ]
             | _ ->
                 let tystr = get_cast_to_mem_expr (ptype, decl) true in
                 [
                   sprintf "if (%s)" (String.concat " && " (List.rev args));
                   "{";
                   "    /* Restore original pointer. */";
                   sprintf "    %s = %s_ptrs[_ptrs_index++];" arg tystr;
                   "    " ^ s;
                   "}";
                 ]);
            (let param_count = get_param_count (ptype, decl, argstruct) in
             flatten_map
               (get_serializer (arg :: args) param_count)
               (get_deepcopy (get_param_atype ptype)));
          ]
        |> List.flatten )
    in
    let params =
      flatten_map (get_serializer [] "1")
        (List.filter is_out_or_inout_ptr plist)
    in
    if params <> [] then String.concat "\n    " params
    else "/* There were no out nor in-out parameters. */"
  in
  [
    (* Verify that the ecall succeeded *)
    "/* Setup output arg struct pointer. */";
    sprintf "_pargs_out = (%s_args_t*)_output_buffer;" fd.fname;
    "OE_ADD_SIZE(_output_buffer_offset, sizeof(*_pargs_out));";
    "";
    "/* Check if the call succeeded. */";
    "if ((_result = _pargs_out->_result) != OE_OK)";
    "    goto done;";
    "";
    "/* Currently exactly _output_buffer_size bytes must be written. */";
    "if (_output_bytes_written != _output_buffer_size)";
    "{";
    "    _result = OE_FAILURE;";
    "    goto done;";
    "}";
    "";
    "/* Unmarshal return value and out, in-out parameters. */";
    ( if fd.rtype <> Void then "*_retval = _pargs_out->_retval;"
    else "/* No return value. */" );
    get_ptr_index_reset get_deepcopy fd.plist;
    get_serialized_buffer_outputs fd.plist;
  ]

(** Generate a cast expression to a specific pointer type. For example,
    [int*] needs to be cast to
    {[
      *(int ( * )[5][6])
    ]}. *)
let get_cast_from_mem_expr (ptype, decl) =
  match ptype with
  | PTVal _ -> ""
  | PTPtr (t, attr) ->
      if is_array decl then
        sprintf "*(%s(*)%s)" (get_tystr t) (get_array_dims decl.array_dims)
      else if is_foreign_array ptype then
        sprintf "/* foreign array */ *(%s*)" (get_tystr t)
      else if attr.pa_rdonly then
        (* for ptrs, only constness is removed; add it back *)
        sprintf "(const %s)" (get_tystr t)
      else ""

(** Generate an expression to call the user function [fd]. *)
let get_call_user_function (fd : func_decl) =
  [
    "/* Call user function. */";
    (match fd.rtype with Void -> "" | _ -> "pargs_out->_retval = ")
    ^ fd.fname ^ "(";
    String.concat ",\n    "
      (List.map
         (fun (ptype, decl) ->
           let cast_expr = get_cast_from_mem_expr (ptype, decl) in
           sprintf "    %spargs_in->%s" cast_expr decl.identifier)
         fd.plist)
    ^ ");";
  ]

(** Generate ecall function definition. *)
let get_ecall_function get_deepcopy (tf : trusted_func) =
  let fd = tf.tf_fdecl in
  [
    sprintf "static void ecall_%s(" fd.fname;
    "    uint8_t* input_buffer,";
    "    size_t input_buffer_size,";
    "    uint8_t* output_buffer,";
    "    size_t output_buffer_size,";
    "    size_t* output_bytes_written)";
    "{";
    (* Variable declarations *)
    "    oe_result_t _result = OE_FAILURE;";
    "";
    "    /* Prepare parameters. */";
    sprintf "    %s_args_t* pargs_in = (%s_args_t*)input_buffer;" fd.fname
      fd.fname;
    sprintf "    %s_args_t* pargs_out = (%s_args_t*)output_buffer;" fd.fname
      fd.fname;
    "";
    "    size_t input_buffer_offset = 0;";
    "    size_t output_buffer_offset = 0;";
    "    OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));";
    "    OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));";
    "";
    (* Buffer validation *)
    "    /* Make sure input and output buffers lie within the enclave. */";
    "    /* oe_is_within_enclave explicitly checks if buffers are null or not. */";
    "    if (!oe_is_within_enclave(input_buffer, input_buffer_size))";
    "        goto done;";
    "";
    "    if (!oe_is_within_enclave(output_buffer, output_buffer_size))";
    "        goto done;";
    "";
    (* Prepare in and in-out parameters *)
    get_in_ptr_setter get_deepcopy fd.plist;
    "";
    (* Prepare out and in-out parameters. The in-out parameter is
         copied to output buffer. *)
    get_out_ptr_setter get_deepcopy fd.plist;
    "";
    "    /* Check that in/in-out strings are null terminated. */"
    (* NOTE: We do not support deep copy for strings, so there is not
         (yet) anything to do here. *);
    (let params =
       List.map
         (fun (ptype, decl) ->
           sprintf
             "    OE_CHECK_NULL_TERMINATOR%s(pargs_in->%s, pargs_in->%s_len);"
             (if is_wstr_ptr ptype then "_WIDE" else "")
             decl.identifier decl.identifier)
         (List.filter
            (fun p -> is_str_or_wstr_ptr p && is_in_or_inout_ptr p)
            fd.plist)
     in
     if params <> [] then String.concat "\n" params
     else "    /* There were no in nor in-out string parameters. */");
    "";
    "    /* lfence after checks. */";
    "    oe_lfence();";
    "";
    (* Call the enclave function *)
    "    " ^ String.concat "\n    " (get_call_user_function fd);
    "";
    (* Mark call as success *)
    "    /* Success. */";
    "    _result = OE_OK;";
    "    *output_bytes_written = output_buffer_offset;";
    "";
    "done:";
    "    if (output_buffer_size >= sizeof(*pargs_out) &&";
    "        oe_is_within_enclave(pargs_out, output_buffer_size))";
    "        pargs_out->_result = _result;";
    "}";
    "";
  ]

(** Generate enclave OCALL wrapper function. *)
let get_ocall_function_wrapper get_deepcopy enclave_name (uf : untrusted_func) =
  let fd = uf.uf_fdecl in
  let allocate_buffer, call_function, free_buffer =
    if uf.uf_is_switchless then
      ( "oe_allocate_switchless_ocall_buffer",
        "oe_switchless_call_host_function",
        "oe_free_switchless_ocall_buffer" )
    else
      ( "oe_allocate_ocall_buffer",
        "oe_call_host_function",
        "oe_free_ocall_buffer" )
  in
  [
    get_wrapper_prototype fd false;
    "{";
    "    oe_result_t _result = OE_FAILURE;";
    "";
    "    /* If the enclave is in crashing/crashed status, new OCALL should fail";
    "       immediately. */";
    "    if (oe_get_enclave_status() != OE_OK)";
    "        return oe_get_enclave_status();";
    "";
    "    /* Marshalling struct. */";
    sprintf "    %s_args_t _args, *_pargs_in = NULL, *_pargs_out = NULL;"
      fd.fname;
    "    " ^ String.concat "\n    " (get_ptr_array get_deepcopy fd.plist);
    "";
    "    /* Marshalling buffer and sizes. */";
    "    size_t _input_buffer_size = 0;";
    "    size_t _output_buffer_size = 0;";
    "    size_t _total_buffer_size = 0;";
    "    uint8_t* _buffer = NULL;";
    "    uint8_t* _input_buffer = NULL;";
    "    uint8_t* _output_buffer = NULL;";
    "    size_t _input_buffer_offset = 0;";
    "    size_t _output_buffer_offset = 0;";
    "    size_t _output_bytes_written = 0;";
    "";
    "    /* Fill marshalling struct. */";
    "    memset(&_args, 0, sizeof(_args));";
    "    " ^ String.concat "\n    " (get_filled_marshal_struct get_deepcopy fd);
    "";
    "    "
    ^ String.concat "\n    " (get_input_buffer get_deepcopy fd allocate_buffer);
    "";
    "    /* Call host function. */";
    "    if ((_result = " ^ call_function ^ "(";
    "             "
    ^ String.concat ",\n             "
        [
          get_function_id enclave_name fd;
          "_input_buffer";
          "_input_buffer_size";
          "_output_buffer";
          "_output_buffer_size";
          "&_output_bytes_written)) != OE_OK)";
        ];
    "        goto done;";
    "";
    "    " ^ String.concat "\n    " (get_output_buffer get_deepcopy fd);
    "";
    "    /* Retrieve propagated errno from OCALL. */";
    ( if uf.uf_propagate_errno then "    oe_errno = _pargs_out->_ocall_errno;\n"
    else sprintf "    /* Errno propagation not enabled. */" );
    "";
    "    _result = OE_OK;";
    "";
    "done:";
    "    if (_buffer)";
    "        " ^ free_buffer ^ "(_buffer);";
    "    return _result;";
    "}";
    "";
  ]

let generate_trusted (ec : enclave_content) (ep : Intel.Util.edger8r_params) =
  let get_deepcopy = get_deepcopy_function ep.experimental ec.comp_defs in
  let tfs = ec.tfunc_decls in
  let ufs = ec.ufunc_decls in
  let ecall_functions =
    if tfs <> [] then flatten_map (get_ecall_function get_deepcopy) tfs
    else [ "/* There were no ecalls. */" ]
  in
  let ecall_table =
    let table = "__oe_ecalls_table" in
    if tfs <> [] then
      [
        sprintf "oe_ecall_func_t %s[] = {" table;
        "    "
        ^ String.concat ",\n    "
            (List.map
               (fun f -> "(oe_ecall_func_t) ecall_" ^ f.tf_fdecl.fname)
               tfs);
        "};";
        "";
        sprintf "size_t %s_size = OE_COUNTOF(%s);" table table;
      ]
    else [ "/* There were no ecalls. */" ]
  in
  let ocall_function_wrappers =
    if ufs <> [] then
      flatten_map (get_ocall_function_wrapper get_deepcopy ec.enclave_name) ufs
    else [ "/* There were no ocalls. */" ]
  in
  [
    sprintf "#include \"%s_t.h\"" ec.file_shortnm;
    "";
    "#include <openenclave/edger8r/enclave.h>";
    "";
    "OE_EXTERNC_BEGIN";
    "";
    "/**** ECALL functions. ****/";
    "";
    String.concat "\n" ecall_functions;
    "/**** ECALL function table. ****/";
    "";
    String.concat "\n" ecall_table;
    "";
    "/**** OCALL function wrappers. ****/";
    "";
    String.concat "\n" ocall_function_wrappers;
    "OE_EXTERNC_END";
    "";
  ]

(* Generate host ECALL wrapper function. *)
let get_host_ecall_wrapper get_deepcopy enclave_name (tf : trusted_func) =
  let fd = tf.tf_fdecl in
  let ecall_function =
    if tf.tf_is_switchless then "oe_switchless_call_enclave_function"
    else "oe_call_enclave_function"
  in
  [
    get_wrapper_prototype fd true;
    "{";
    "    oe_result_t _result = OE_FAILURE;";
    "";
    "    /* Marshalling struct. */";
    sprintf "    %s_args_t _args, *_pargs_in = NULL, *_pargs_out = NULL;"
      fd.fname;
    "";
    "    /* Marshalling buffer and sizes. */";
    "    size_t _input_buffer_size = 0;";
    "    size_t _output_buffer_size = 0;";
    "    size_t _total_buffer_size = 0;";
    "    uint8_t* _buffer = NULL;";
    "    uint8_t* _input_buffer = NULL;";
    "    uint8_t* _output_buffer = NULL;";
    "    size_t _input_buffer_offset = 0;";
    "    size_t _output_buffer_offset = 0;";
    "    size_t _output_bytes_written = 0;";
    "";
    "    /* Deep copy buffer. */";
    "    " ^ String.concat "\n    " (get_ptr_array get_deepcopy fd.plist);
    "";
    "    /* Fill marshalling struct. */";
    "    memset(&_args, 0, sizeof(_args));";
    "    " ^ String.concat "\n    " (get_filled_marshal_struct get_deepcopy fd);
    "";
    "    " ^ String.concat "\n    " (get_input_buffer get_deepcopy fd "oe_malloc");
    "";
    "    /* Call enclave function. */";
    "    if ((_result = " ^ ecall_function ^ "(";
    "             "
    ^ String.concat ",\n             "
        [
          "enclave";
          get_function_id enclave_name fd;
          "_input_buffer";
          "_input_buffer_size";
          "_output_buffer";
          "_output_buffer_size";
          "&_output_bytes_written)) != OE_OK)";
        ];
    "        goto done;";
    "";
    "    " ^ String.concat "\n    " (get_output_buffer get_deepcopy fd);
    "";
    "    _result = OE_OK;";
    "";
    "done:";
    "    if (_buffer)";
    "        free(_buffer);";
    "";
    "    " ^ String.concat "\n    " (get_ptr_free_expr get_deepcopy fd.plist);
    "";
    "    return _result;";
    "}";
    "";
  ]

(* Generate ocall function. *)
let get_ocall_function get_deepcopy (uf : untrusted_func) =
  let fd = uf.uf_fdecl in
  [
    sprintf "static void ocall_%s(" fd.fname;
    "    uint8_t* input_buffer,";
    "    size_t input_buffer_size,";
    "    uint8_t* output_buffer,";
    "    size_t output_buffer_size,";
    "    size_t* output_bytes_written)";
    "{";
    (* Variable declarations *)
    "    oe_result_t _result = OE_FAILURE;";
    "    OE_UNUSED(input_buffer_size);";
    "";
    "    /* Prepare parameters. */";
    sprintf "    %s_args_t* pargs_in = (%s_args_t*)input_buffer;" fd.fname
      fd.fname;
    sprintf "    %s_args_t* pargs_out = (%s_args_t*)output_buffer;" fd.fname
      fd.fname;
    "";
    "    size_t input_buffer_offset = 0;";
    "    size_t output_buffer_offset = 0;";
    "    OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));";
    "    OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));";
    "";
    (* Buffer validation *)
    "    /* Make sure input and output buffers are valid. */";
    "    if (!input_buffer || !output_buffer) {";
    "        _result = OE_INVALID_PARAMETER;";
    "        goto done;";
    "    }";
    "";
    (* Prepare in and in-out parameters *)
    get_in_ptr_setter get_deepcopy fd.plist;
    "";
    (* Prepare out and in-out parameters: the in-out parameter is
       copied to output buffer. *)
    get_out_ptr_setter get_deepcopy fd.plist;
    "";
    (* Call the host function *)
    "    " ^ String.concat "\n    " (get_call_user_function fd);
    "";
    "    /* Propagate errno back to enclave. */";
    ( if uf.uf_propagate_errno then "    pargs_out->_ocall_errno = errno;"
    else "    /* Errno propagation not enabled. */" );
    "";
    (* Mark call as success *)
    "    /* Success. */";
    "    _result = OE_OK;";
    "    *output_bytes_written = output_buffer_offset;";
    "";
    "done:";
    "    if (pargs_out && output_buffer_size >= sizeof(*pargs_out))";
    "        pargs_out->_result = _result;";
    "}";
    "";
  ]

let generate_untrusted (ec : enclave_content) (ep : Intel.Util.edger8r_params) =
  let get_deepcopy = get_deepcopy_function ep.experimental ec.comp_defs in
  let host_ecall_wrappers =
    let tfs = ec.tfunc_decls in
    if tfs <> [] then
      flatten_map (get_host_ecall_wrapper get_deepcopy ec.enclave_name) tfs
    else [ "/* There were no ecalls. */" ]
  in
  let ocall_functions =
    let ufs = ec.ufunc_decls in
    if ufs <> [] then flatten_map (get_ocall_function get_deepcopy) ufs
    else [ "/* There were no ocalls. */" ]
  in
  let ocall_table =
    [
      sprintf "static oe_ocall_func_t __%s_ocall_function_table[] = {"
        ec.enclave_name;
      "    "
      ^ String.concat "\n    "
          (List.map
             (fun f -> "(oe_ocall_func_t) ocall_" ^ f.uf_fdecl.fname ^ ",")
             ec.ufunc_decls);
      "    NULL";
      "};";
    ]
  in
  [
    sprintf "#include \"%s_u.h\"" ec.file_shortnm;
    "";
    "#include <openenclave/edger8r/host.h>";
    "";
    "OE_EXTERNC_BEGIN";
    "";
    "/**** ECALL function wrappers. ****/";
    "";
    String.concat "\n" host_ecall_wrappers;
    "/**** OCALL functions. ****/";
    "";
    String.concat "\n" ocall_functions;
    "/**** OCALL function table. ****/";
    "";
    String.concat "\n" ocall_table;
    "";
    sprintf "oe_result_t oe_create_%s_enclave(" ec.enclave_name;
    "    const char* path,";
    "    oe_enclave_type_t type,";
    "    uint32_t flags,";
    "    const oe_enclave_setting_t* settings,";
    "    uint32_t setting_count,";
    "    oe_enclave_t** enclave)";
    "{";
    "    return oe_create_enclave(";
    "               path,";
    "               type,";
    "               flags,";
    "               settings,";
    "               setting_count,";
    sprintf "               __%s_ocall_function_table," ec.enclave_name;
    sprintf "               %d," (List.length ec.ufunc_decls);
    "               enclave);";
    "}";
    "";
    "OE_EXTERNC_END";
    "";
  ]
