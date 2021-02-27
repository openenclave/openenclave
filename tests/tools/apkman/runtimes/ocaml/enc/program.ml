(* File calc.ml *)
let calc_main () =
  try
    Printf.printf "Calculator. Enter expressions ...";
    print_newline ();
    let lexbuf = Lexing.from_channel stdin in
    while true do
      let result = Parser.main Lexer.token lexbuf in
      print_int result;
      print_newline();
      flush stdout
    done
  with Lexer.Eof -> ()


type 'a tree = Empty
             | Node of 'a * 'a tree * 'a tree

let rec preorder f = function
    Empty        -> ()
  | Node (v,l,r) -> f v;
                    preorder f l;
                    preorder f r

let rec inorder f = function
    Empty        -> ()
  | Node (v,l,r) -> inorder f l;
                    f v;
                    inorder f r

let rec postorder f = function
    Empty        -> ()
  | Node (v,l,r) -> postorder f l;
                    postorder f r;
                    f v

let levelorder f x =
  let queue = Queue.create () in
  Queue.add x queue;
  while not (Queue.is_empty queue) do
    match Queue.take queue with
      Empty         -> ()
    | Node (v, l,r) -> f v;
                       Queue.add l queue;
                       Queue.add r queue
  done

let tree =
  Node (1,
        Node (2,
              Node (4,
                    Node (7, Empty, Empty),
                    Empty),
              Node (5, Empty, Empty)),
        Node (3,
              Node (6,
                    Node (8, Empty, Empty),
                    Node (9, Empty, Empty)),
              Empty))


let print_tree tos tree =
  let rec loop margin = function
    | Empty -> ()
    | Node (v, a,b) ->
       loop (margin ^ "    ") a ;
       Printf.printf "%s%s\n%!" margin (tos v);
       loop (margin ^ "    ") b
  in
  loop "   " tree

let traverse_tree () =
  print_tree string_of_int tree; print_newline();
  preorder   (Printf.printf "%d ") tree; print_newline ();
  inorder    (Printf.printf "%d ") tree; print_newline ();
  postorder  (Printf.printf "%d ") tree; print_newline ();
  levelorder (Printf.printf "%d ") tree; print_newline ()


let ocaml_main () =
  traverse_tree();
  calc_main()  

let _ = Callback.register "ocaml_main" ocaml_main
