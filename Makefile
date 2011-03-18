OCAMLC = ocamlfind ocamlc -g -package fileutils.str,sqlite3
OCAMLOPT = ocamlfind ocamlopt -g -package fileutils.str,sqlite3
ML_CFLAGS = $(foreach u,$(shell pkg-config --cflags nss),-ccopt $(u))
ML_LFLAGS = $(foreach u,$(shell pkg-config --libs nss),-ccopt $(u))

.PHONY: all clean

all: mozilla-passwords

clean:
	rm -f *~ *.cm[oxi] *.o mozilla-passwords

mozilla-passwords: main.cmo nss_stubs.o main_stubs.o
	$(OCAMLC) $(ML_LFLAGS) -custom -linkpkg -o $@ $^

%.cmx: %.ml
	$(OCAMLOPT) -c $<

%.cmo: %.ml
	$(OCAMLC) -c $<

%.o: %.c
	$(OCAMLC) $(ML_CFLAGS) -c $<
