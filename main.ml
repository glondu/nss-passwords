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

exception NSS_init_failed
exception NSS_cleanup_failed
exception NSS_base64_decode_failed of string * int
exception NSS_decrypt_failed of string * int

let () = Callback.register_exception "NSS_init_failed"
  NSS_init_failed
let () = Callback.register_exception "NSS_cleanup_failed"
  NSS_cleanup_failed
let () = Callback.register_exception "NSS_base64_decode_failed"
  (NSS_base64_decode_failed ("", 0))
let () = Callback.register_exception "NSS_decrypt_failed"
  (NSS_decrypt_failed ("", 0))

external nss_cleanup : unit -> unit = "caml_nss_cleanup"
external nss_init : string -> unit = "caml_nss_init"
external do_decrypt : password:string -> data:string -> string = "caml_do_decrypt"

let () = at_exit nss_cleanup

let dir = read_line ()
let password = read_line ()
let data = read_line () ^ "\n"

let () = nss_init dir
let () = print_endline (do_decrypt ~password ~data)
