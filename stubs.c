/* ***** BEGIN LICENSE BLOCK *****
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
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
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
 * This file was adapted from nss/mozilla/security/nss/cmd/pwdecrypt.c for
 * use with Objective Caml.
 * Copyright (C) 2010 Stephane Glondu <steph@glondu.net>.
 *
 * ***** END LICENSE BLOCK ***** */

#include <nspr/nspr.h>
#include <string.h>
#include <nss/nss.h>
#include <nss/cert.h>
#include <nss/pk11func.h>
#include <nss/nssb64.h>

#include <nss/pk11sdr.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>

char *password_func(PK11SlotInfo *slot, PRBool retry, void *arg) {
  if (retry) {
    return NULL;
  } else {
    return PL_strdup(arg);
  }
}

CAMLprim value caml_nss_cleanup(value unit) {
  CAMLparam1(unit);
  if (NSS_Shutdown() != SECSuccess) {
    caml_raise_constant(*caml_named_value("NSS_cleanup_failed"));
  }
  PR_Cleanup ();
  CAMLreturn(Val_unit);
}

CAMLprim value caml_nss_init(value path) {
  CAMLparam1(path);
  int rv;

  PK11_SetPasswordFunc(password_func);
  rv = NSS_Init(String_val(path));
  if (rv != SECSuccess) {
    caml_raise_constant(*caml_named_value("NSS_init_failed"));
  }
  CAMLreturn(Val_unit);
}

CAMLprim value caml_do_decrypt(value password, value data) {
  CAMLparam2(password, data);
  CAMLlocal1(res);
  char *passwordString = String_val(password);
  char *dataString = String_val(data);
  int strLen = caml_string_length(data);
  SECItem *decoded = NSSBase64_DecodeBuffer(NULL, NULL, dataString, strLen);
  SECStatus rv;
  SECItem    result = { siBuffer, NULL, 0 };

  if ((decoded == NULL) || (decoded->len == 0)) {
    /* Base64 decoding failed */
    res = Val_int(PORT_GetError());
    if (decoded) {
      SECITEM_FreeItem(decoded, PR_TRUE);
    }
    {
      value args[] = { data, res };
      caml_raise_with_args(*caml_named_value("NSS_base64_decode_failed"), 2, args);
    }
  }
  /* Base64 decoding succeeded */
  rv = PK11SDR_Decrypt(decoded, &result, passwordString);
  SECITEM_ZfreeItem(decoded, PR_TRUE);
  if (rv == SECSuccess) {
    res = caml_alloc_string(result.len);
    memcpy(String_val(res), result.data, result.len);
    SECITEM_ZfreeItem(&result, PR_FALSE);
    CAMLreturn(res);
  }
  /* decryption failed */
  res = Val_int(PORT_GetError());
  {
    value args[] = { data, res };
    caml_raise_with_args(*caml_named_value("NSS_decrypt_failed"), 2, args);
  }
}
