OCAMLC = ocamlfind ocamlc -g -package fileutils.str,sqlite3
OCAMLOPT = ocamlfind ocamlopt -g -package fileutils.str,sqlite3
ML_CFLAGS = $(foreach u,$(shell pkg-config --cflags nss),-ccopt $(u))
ML_LFLAGS = $(foreach u,$(shell pkg-config --libs nss),-cclib $(u))

.PHONY: all clean

all: nss-passwords

clean:
	rm -f *~ *.cm[oxi] *.o nss-passwords

nss-passwords: main.cmo nss_stubs.o main_stubs.o
	$(OCAMLC) -o $@ $^ $(ML_LFLAGS) -custom -linkpkg

%.cmx: %.ml
	$(OCAMLOPT) -c $<

%.cmo: %.ml
	$(OCAMLC) -c $<

%.o: %.c
	$(OCAMLC) $(ML_CFLAGS) -c $<
