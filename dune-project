(lang dune 3.11)
(name nss-passwords)

(generate_opam_files true)

(package
 (name nss-passwords)
 (synopsis "Read passwords from a Mozilla keyring")
 (depends
  conf-pkg-config
  dune
  dune-configurator
  fileutils
  atdgen
  yojson))
