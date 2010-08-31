OCAMLOPT = ocamlfind ocamlopt -g -package fileutils.str,sqlite3
ML_CFLAGS = $(foreach u,$(shell pkg-config --cflags nss),-ccopt $(u))
ML_LFLAGS = $(foreach u,$(shell pkg-config --libs nss),-ccopt $(u))

.PHONY: all clean

all: mozilla-passwords

clean:
	rm -f *~ *.cm[oxi] *.o mozilla-passwords

mozilla-passwords: main.cmx nss_stubs.o main_stubs.o
	$(OCAMLOPT) $(ML_LFLAGS) -linkpkg -o $@ $^

%.cmx: %.ml
	$(OCAMLOPT) -c $<

%.o: %.c
	$(OCAMLOPT) $(ML_CFLAGS) -c $<
