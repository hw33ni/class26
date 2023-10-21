LDLIBS=-lpcap

all: tcp-block

tcp-block: tcp-block.o mac.o ethhdr.o ip.o iphdr.o tcphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f tcp-block *.o

remake: clean all
