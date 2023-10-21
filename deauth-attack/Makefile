LDLIBS = -lpcap

all: deauth-attack

deauth-attack: deauth.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f deauth-attack *.o

remake: clean all