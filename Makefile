OCAMLC = ocamlfind ocamlc -g -package fileutils.str,sqlite3,atdgen
OCAMLOPT = ocamlfind ocamlopt -g -package fileutils.str,sqlite3,atdgen

ML_CFLAGS = $(foreach u,$(shell pkg-config --cflags nss),-ccopt $(u))
ML_LFLAGS = $(foreach u,$(shell pkg-config --libs nss),-cclib $(u))

.PHONY: all clean

all: nss-passwords

clean:
	rm -f *~ *.cm[oxi] *.o nss-passwords

nss-passwords: json_types_t.cmo json_types_j.cmo main.cmo nss_stubs.o main_stubs.o
	$(OCAMLC) -o $@ $^ $(ML_LFLAGS) -custom -linkpkg

%.cmx: %.ml
	$(OCAMLOPT) -c $<

%.cmo: %.ml
	$(OCAMLC) -c $<

%.cmi: %.mli
	$(OCAMLC) -c $<

%.o: %.c
	$(OCAMLC) $(ML_CFLAGS) -c $<

%_j.ml %_j.mli: %.atd
	atdgen -j -j-std $<

%_t.ml %_t.mli: %.atd
	atdgen -t $<

json_types_t.cmo: json_types_t.cmi
json_types_j.ml: json_types_t.ml
json_types_j.cmo: json_types_j.cmi
