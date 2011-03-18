(**************************************************************************)
(*  Copyright © 2010 Stéphane Glondu <steph@glondu.net>                   *)
(*                                                                        *)
(*  This program is free software: you can redistribute it and/or modify  *)
(*  it under the terms of the GNU Affero General Public License as        *)
(*  published by the Free Software Foundation, either version 3 of the    *)
(*  License, or (at your option) any later version, with the additional   *)
(*  exemption that compiling, linking, and/or using OpenSSL is allowed.   *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful, but   *)
(*  WITHOUT ANY WARRANTY; without even the implied warranty of            *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *)
(*  Affero General Public License for more details.                       *)
(*                                                                        *)
(*  You should have received a copy of the GNU Affero General Public      *)
(*  License along with this program.  If not, see                         *)
(*  <http://www.gnu.org/licenses/>.                                       *)
(**************************************************************************)

(** C interface *)

exception NSS_init_failed
exception NSS_cleanup_failed
exception NSS_base64_decode_failed of string * int
exception NSS_decrypt_failed of string * int * exn option

let () = Callback.register_exception "NSS_init_failed"
  NSS_init_failed
let () = Callback.register_exception "NSS_cleanup_failed"
  NSS_cleanup_failed
let () = Callback.register_exception "NSS_base64_decode_failed"
  (NSS_base64_decode_failed ("", 0))
let () = Callback.register_exception "NSS_decrypt_failed"
  (NSS_decrypt_failed ("", 0, None))

external nss_cleanup : unit -> unit = "caml_nss_cleanup"
external nss_init : string -> unit = "caml_nss_init"
external do_decrypt : callback:(bool -> string) -> data:string -> string = "caml_do_decrypt"
external ttyname : Unix.file_descr -> string = "caml_ttyname"

(** Command-line arguments parsing and initialization *)

let dir = ref ""
let pinentry = ref "pinentry"
let queries = ref []

let spec =  Arg.align [
  "-d", Arg.Set_string dir, "profile directory (default: Firefox default profile)";
  "-p", Arg.Set_string pinentry, "pinentry program to use (default: pinentry)";
]
let usage_msg = "nss-passwords [-d <dir>] [-p <pinentry>] query [...]"

exception Found of string

let () =
  Arg.parse spec (fun x -> queries := x :: !queries) usage_msg;
  if !queries = [] then begin
    Arg.usage spec usage_msg;
    exit 1
  end;
  if !dir = "" then begin
    try
      let () = FileUtil.find
        ~follow:FileUtil.Follow
        ~match_compile:FileUtilStr.match_compile
        (FileUtil.And (FileUtil.Is_dir, FileUtil.Match ".*\\.default$"))
        (FilePath.concat (Sys.getenv "HOME") ".mozilla/firefox")
        (fun _ x -> raise (Found x))
        ()
      in
      Printf.eprintf "No default profile directory found\n";
      exit 1
    with Found x -> dir := x
  end else if not (FileUtil.test FileUtil.Is_dir !dir) then begin
    Printf.eprintf "Invalid profile directory: %s\n" !dir;
    exit 1
  end;
  nss_init !dir;
  at_exit nss_cleanup

let db = Sqlite3.db_open (FilePath.concat !dir "signons.sqlite")
let () = at_exit (fun () -> let r = Sqlite3.db_close db in assert (r = true))

(** Decrypt passwords *)

let check line =
  assert (String.length line >= 2 && String.sub line 0 2 = "OK");
  ()

let lc_ctype =
  try
    Some (Sys.getenv "LC_ALL")
  with Not_found ->
    try
      Some (Sys.getenv "LANG")
    with Not_found ->
      None

let callback retry =
  if retry then
    failwith "invalid password"
  else
    let (stdin, stdout) as child = Unix.open_process !pinentry in
    check (input_line stdin);
    let ttyname =
      try ttyname Unix.stdin
      with Unix.Unix_error(_, _, _) -> failwith "stdin is not a tty"
    in
    Printf.fprintf stdout "OPTION ttyname=%s\n%!" ttyname;
    check (input_line stdin);
    begin match lc_ctype with
      | Some x ->
        Printf.fprintf stdout "OPTION lc-ctype=%s\n%!" x;
        check (input_line stdin)
      | None -> ()
    end;
    Printf.fprintf stdout "GETPIN\n%!";
    let line = input_line stdin in
    let _ = Unix.close_process child in
    let n = String.length line in
    if n > 2 then
      String.sub line 2 (n-2)
    else
      failwith "missing password"

let quote_query buf x =
  Buffer.add_string buf "'%";
  String.iter
    (function
      | '\'' -> Buffer.add_string buf "''"
      | '%' -> Buffer.add_string buf "x%"
      | '_' -> Buffer.add_string buf "x_"
      | 'x' -> Buffer.add_string buf "xx"
      | c -> Buffer.add_char buf c)
    x;
  Buffer.add_string buf "%'"

let results = ref []

let process_row = function
  | [| hostname; encryptedUsername; encryptedPassword |] ->
    let username = do_decrypt ~callback ~data:encryptedUsername in
    let password = do_decrypt ~callback ~data:encryptedPassword in
    results := (hostname, username, password) :: !results
  | _ -> assert false

let exec query =
  let buf = Buffer.create (2 * String.length query + 128) in
  Printf.bprintf buf
    "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins WHERE hostname LIKE %a ESCAPE 'x';"
    quote_query query;
  let r = Sqlite3.exec_not_null_no_headers ~cb:process_row db (Buffer.contents buf) in
  assert (r = Sqlite3.Rc.OK)

let () =
  try
    List.iter exec !queries;
    let results = List.sort compare !results in
    let (a, b, c) = List.fold_left
      (fun (a, b, c) (x, y, z) ->
        let a = max a (String.length x) in
        let b = max b (String.length y) in
        let c = max c (String.length z) in
        (a, b, c))
      (0, 0, 0)
      results
    in
    let fmt = Printf.ksprintf
      (fun fmt -> Scanf.format_from_string fmt "%s %s %s")
      "| %%-%ds | %%-%ds | %%-%ds |\n" a b c
    in
    List.iter (fun (x, y, z) -> Printf.printf fmt x y z) results
  with
    | NSS_decrypt_failed(_, _, Some e) ->
      Printf.eprintf "Error while decrypting: %s\n" (Printexc.to_string e);
      exit 2
