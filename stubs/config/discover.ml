module C = Configurator.V1

let () =
  C.main ~name:"nss-pkg-config" (fun c ->
      let conf =
        match C.Pkg_config.get c with
        | None -> failwith "pkg-config is missing"
        | Some pc -> (
            match C.Pkg_config.query pc ~package:"nss" with
            | None -> failwith "nss is missing in pkg-config"
            | Some deps -> deps)
      in
      C.Flags.write_sexp "c_flags.sexp" conf.cflags;
      C.Flags.write_sexp "c_library_flags.sexp" conf.libs)
