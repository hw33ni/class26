LDLIBS=-lpcap

all: airodump

airodump: airodump.o mac.o airodump_hw.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump
	rm -f *.o