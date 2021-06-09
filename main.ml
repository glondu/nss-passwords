(* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Initial Developer of the Original Code is
 * Stéphane Glondu <steph@glondu.net>
 * Portions created by the Initial Developer are Copyright (C) 2010-2011
 * the Initial Developer. All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** *)

open Json_types_j

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
let json_output = ref false

let spec =  Arg.align [
  "-d", Arg.Set_string dir, "profile directory (default: Firefox default profile)";
  "-p", Arg.Set_string pinentry, "pinentry program to use (default: pinentry)";
  "-j", Arg.Set json_output, "output result in JSON";
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
    results := {hostname; username; password} :: !results
  | _ -> assert false

let exec db query =
  let buf = Buffer.create (2 * String.length query + 128) in
  Printf.bprintf buf
    "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins WHERE hostname LIKE %a ESCAPE 'x';"
    quote_query query;
  let r = Sqlite3.exec_not_null_no_headers ~cb:process_row db (Buffer.contents buf) in
  assert (r = Sqlite3.Rc.OK)

let exec_sqlite () =
  let db = Sqlite3.db_open (FilePath.concat !dir "signons.sqlite") in
  List.iter (exec db) !queries;
  let r = Sqlite3.db_close db in
  assert (r = true)

let json_process logins query =
  let rex = Str.regexp (".*" ^ Str.quote query ^ ".*") in
  List.iter
    (fun l ->
      let hostname = l.ihostname in
      if Str.string_match rex hostname 0 then (
        let username = do_decrypt ~callback ~data:l.iencryptedUsername in
        let password = do_decrypt ~callback ~data:l.iencryptedPassword in
        results := {hostname; username; password} :: !results
      )
    ) logins

let exec_json () =
  let ic = open_in (FilePath.concat !dir "logins.json") in
  let ls = Yojson.init_lexer () in
  let lb = Lexing.from_channel ic in
  let logins = read_logins ls lb in
  close_in ic;
  List.iter (json_process logins.logins) !queries

let print_as_table results =
  let (a, b, c) =
    List.fold_left
      (fun (a, b, c) o ->
        let a = max a (String.length o.hostname) in
        let b = max b (String.length o.username) in
        let c = max c (String.length o.password) in
        (a, b, c))
      (0, 0, 0)
      results
  in
  List.iter
    (fun o ->
      Printf.printf "| %-*s | %-*s | %-*s |\n" a o.hostname b o.username c o.password
    ) results

let print_as_json results =
  print_endline (string_of_output results)

let () =
  try
    (if Sys.file_exists (FilePath.concat !dir "logins.json")
     then exec_json ()
     else exec_sqlite ()
    );
    let results = List.sort compare !results in
    (if !json_output then print_as_json else print_as_table) results
  with
    | NSS_decrypt_failed(_, _, Some e) ->
      Printf.eprintf "Error while decrypting: %s\n" (Printexc.to_string e);
      exit 2
