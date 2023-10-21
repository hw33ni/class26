#include <cstdio>
#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <netinet/in.h>
#include <map>
#include "airodump_hw.h"

using namespace std;

void usage() {
        cout << "syntax : airodump <interface>\n";
        cout << "sample : airodump mon0\n";
}

map<string, pair<int, string>> info;

int main(int argc, char* argv[]) {
    	if (argc != 2 ) {
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

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        rf* radioPacket = (rf*) packet;
        uint16_t radio_len = radioPacket -> it_len;
        bf* beacon = (bf*) (packet + radio_len);
        if(beacon->type != 0x80) continue; // version 10 check
        
        Mac bssid = beacon->bssid;
        ff* fixedFrame = (ff*) ((u_char*)beacon + sizeof(bf));
        tf* taggedFrame = (tf*) ((u_char*)fixedFrame + 12);

        string essid = string(taggedFrame->essid, taggedFrame->len);

        if(info.find((string)bssid) == info.end()) {

            info[(string)bssid]  = {1, essid};
        }
        else info[(string)bssid].first++;

        system("clear");

        cout << left << setw(20) << "BSSID" << setw(10) << "BEACONS" << setw(40) << "ESSID" << endl;
        for(auto iter:info){
            cout << setw(20) << left << iter.first << setw(10) << left << iter.second.first << setw(40) << left << iter.second.second;
        }

    }
    pcap_close(handle);
}