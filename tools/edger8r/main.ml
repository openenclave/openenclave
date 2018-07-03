(* 
   main.ml is used to assemble both the plugin 
   and edger8r into a single executable.
   There may be some way to avoid duplicating the 
   main function from CodeGen.ml here.
*)
open Emitter


let main =  
  let progname = Sys.argv.(0) in
  let argc = Array.length Sys.argv in
  let args = if argc = 1 then [||] else Array.sub Sys.argv 1 (argc-1) in
  let cmd_params = Util.parse_cmdline progname (Array.to_list args) in

  let real_ast_handler fname =
    try
      CodeGen.gen_enclave_code (CodeGen.start_parsing fname) cmd_params
    with
      Failure s -> (Printf.eprintf "error: %s\n" s; exit (-1))
  in
    if cmd_params.Util.input_files = [] then Util.usage progname
    else List.iter real_ast_handler cmd_params.Util.input_files

