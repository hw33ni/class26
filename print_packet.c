#include "print_packet.h"

void p_mac(u8* mac) {

	for(int i = 0;i < 6;i++){
		printf("%02x", mac[i]);
		if(i < 5) printf(":");
	}
	printf("\n");
	return;
}

void p_ip(u8* ip) {
	for(int i = 0;i < 4;i++) {
		printf("%u", ip[i]);
		if(i < 3) printf(".");
	}
	printf("\n");
	return;
}

void p_port(u16 port) {
	printf("%u\n", port);
	return;
}

void mypcap(pcap_t* pcap)
{
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		
		hdr1* eth = (hdr1*) packet;
		hdr2* ip = (hdr2*) (packet + sizeof(hdr1));
		hdr3* tcp = (hdr3*) (packet + sizeof(hdr2) + sizeof(hdr3));
		
		if(ip->ip_p != IPPROTO_TCP){
			printf("NOT TCP!!\n");
		} else {
			printf("%u bytes captured\n", header->caplen);
			printf("src mac : ");
			p_mac(eth->ether_shost);
			printf("dst mac : ");
			p_mac(eth->ether_dhost);
			printf("src ip : ");
			p_ip(ip->ip_src);
			printf("dst ip : ");
			p_ip(ip->ip_dst);
			printf("src port : ");
			p_port(ntohs(tcp->th_sport));
			printf("dst port : ");
			p_port(ntohs(tcp->th_dport));
			
			u8* pl = (u8*) tcp + ((u8) tcp->th_off << 2);
			u16 size = ntohs(ip->ip_len) - ((u16) 4 << 2) - ((u16) tcp->th_off << 2);
			printf("payload : %u byte\npayload's value : ", size);
			for(int i = 0;i < (size > 8 ? 8 : size);i++) printf("%x ", pl[i]);
			printf("\n");
		}
	}
	return;
}
