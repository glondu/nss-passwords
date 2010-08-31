/**************************************************************************/
/*  Copyright © 2010 Stéphane Glondu <steph@glondu.net>                   */
/*                                                                        */
/*  This program is free software: you can redistribute it and/or modify  */
/*  it under the terms of the GNU Affero General Public License as        */
/*  published by the Free Software Foundation, either version 3 of the    */
/*  License, or (at your option) any later version, with the additional   */
/*  exemption that compiling, linking, and/or using OpenSSL is allowed.   */
/*                                                                        */
/*  This program is distributed in the hope that it will be useful, but   */
/*  WITHOUT ANY WARRANTY; without even the implied warranty of            */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     */
/*  Affero General Public License for more details.                       */
/*                                                                        */
/*  You should have received a copy of the GNU Affero General Public      */
/*  License along with this program.  If not, see                         */
/*  <http://www.gnu.org/licenses/>.                                       */
/**************************************************************************/

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/unixsupport.h>

CAMLprim value caml_ttyname(value ml_fd) {
  CAMLparam1(ml_fd);
  char *r = ttyname(Int_val(ml_fd));
  if (r) {
    CAMLreturn(caml_copy_string(r));
  } else {
    uerror("ttyname", Nothing);
  }
}
