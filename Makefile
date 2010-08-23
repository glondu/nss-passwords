OCAMLOPT = ocamlopt -g
ML_CFLAGS = $(foreach u,$(shell pkg-config --cflags nss),-ccopt $(u))
ML_LFLAGS = $(foreach u,$(shell pkg-config --libs nss),-ccopt $(u))

.PHONY: all clean

all: mozilla-passwords

clean:
	rm -f *~ *.cm[oxi] *.o mozilla-passwords

mozilla-passwords: main.cmx stubs.o
	$(OCAMLOPT) $(ML_LFLAGS) -o $@ $^

%.cmx: %.ml
	$(OCAMLOPT) -c $<

%.o: %.c
	$(OCAMLOPT) $(ML_CFLAGS) -c $<
