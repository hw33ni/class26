all: pcap-test

pcap-test: print_packet.o  main.o
	g++ -o pcap-test print_packet.o main.o -lpcap

main.o: libnet.h print_packet.h main.c

print_packet.o: libnet.h print_packet.h print_packet.c

clean:
	rm -f pcap-test *.o
