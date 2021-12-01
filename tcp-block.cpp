#include <bits/stdc++.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>


#include "mac.h"
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

using namespace std;

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

Mac myMac;
Ip myIp;

char blockSite[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";


char *strnstr(const char *big, const char *little, size_t len)
{
	size_t llen;
	size_t blen;
	size_t i;

	if (!*little)
		return ((char *)big);
	llen = strlen(little);
	blen = strlen(big);
	i = 0;
	if (blen < llen || len < llen)
		return (0);
	while (i + llen <= len)
	{
		if (big[i] == *little && !strncmp(big + i, little, llen))
			return ((char *)big + i);
		i++;
	}
	return (0);
}

void initMyIpMac(const char* dev)
{
    struct ifreq ifr;
	int s;
	s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s == -1)
    {
        perror("socket creation failed");
        exit(-1);
    }

	ifr.ifr_addr.sa_family = AF_INET;

    memcpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (!ioctl(s, SIOCGIFHWADDR, &ifr)) myMac = Mac((uint8_t*)(ifr.ifr_hwaddr.sa_data));
    if (!ioctl(s, SIOCGIFADDR, &ifr)) myIp = Ip(std::string(inet_ntoa(((struct sockaddr_in* )&ifr.ifr_addr)->sin_addr)));
	close(s);
	return;
}

bool sendF(pcap_t* handle, EthHdr eh, IpHdr ih, TcpHdr th, unsigned char* pl, int pll,  int f)
{
    int dataSize = ih.total_length - (ih.header_length << 2) - (th.doff << 2);
    
    eh.init(eh.dmac_, myMac);
    ih.init(5, htons(40), ih.flag_offset, ih.ttl, ih.sip_, ih.dip_);
    th.init(th.source, th.dest, th.seq + htonl(dataSize), th.ack_seq, 5, 0x4 + 0x10, htons(TcpHdr::calcChecksum(&ih, &th)));


    int pktSize = sizeof(eh) + sizeof(ih) + sizeof(th) + pll;
    void* ptr = malloc(pktSize);
    if(ptr == nullptr) return 0;

    memcpy(ptr, &eh, sizeof(eh));
    memcpy(ptr+sizeof(eh), &ih, sizeof(ih));
    memcpy(ptr+sizeof(eh)+sizeof(ih), &th, sizeof(th));
    memcpy(ptr+sizeof(eh)+sizeof(ih)+sizeof(th), pl, pll);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ptr), pktSize);
    if (res != 0) {
	    fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    return false;
    } else cout << "block Forward" << endl;

    free(ptr);
    return true;
}

bool sendBF(pcap_t* handle, EthHdr eh, IpHdr ih, TcpHdr th, unsigned char* pl, int pll,  int f)
{
    int dataSize = ih.total_length - (ih.header_length << 2) - (th.doff << 2);
    
    eh.init(eh.smac_, myMac);
    ih.init(5, htons(40 + pll), ih.flag_offset, 137, ih.dip_, ih.sip_);
    th.init(th.dest, th.source, th.ack_seq, th.seq + htonl(dataSize), 5, 0x1+ 0x10, htons(TcpHdr::calcChecksum(&ih, &th)));


    int pktSize = sizeof(eh) + sizeof(ih) + sizeof(th) + pll;
    void* ptr = malloc(pktSize);
    if(ptr == nullptr) return 0;

    memcpy(ptr, &eh, sizeof(eh));
    memcpy(ptr+sizeof(eh), &ih, sizeof(ih));
    memcpy(ptr+sizeof(eh)+sizeof(ih), &th, sizeof(th));
    memcpy(ptr+sizeof(eh)+sizeof(ih)+sizeof(th), pl, pll);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ptr), pktSize);
    if (res != 0) {
	    fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    return false;
    } else cout << "block Backward FIN" << endl;

    free(ptr);
    return true;
}

bool sendBR(pcap_t* handle, EthHdr eh, IpHdr ih, TcpHdr th, unsigned char* pl, int pll,  int f)
{
    int dataSize = ih.total_length - (ih.header_length << 2) - (th.doff << 2);
    
    eh.init(eh.smac_, myMac);
    ih.init(5, htons(40 + pll), ih.flag_offset, 137, ih.dip_, ih.sip_);
    th.init(th.dest, th.source, th.ack_seq, th.seq + htonl(dataSize), 5, 0x4 + 0x10, htons(TcpHdr::calcChecksum(&ih, &th)));


    int pktSize = sizeof(eh) + sizeof(ih) + sizeof(th) + pll;
    void* ptr = malloc(pktSize);
    if(ptr == nullptr) return 0;

    memcpy(ptr, &eh, sizeof(eh));
    memcpy(ptr+sizeof(eh), &ih, sizeof(ih));
    memcpy(ptr+sizeof(eh)+sizeof(ih), &th, sizeof(th));
    memcpy(ptr+sizeof(eh)+sizeof(ih)+sizeof(th), pl, pll);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ptr), pktSize);
    if (res != 0) {
	    fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
	    return false;
    } else cout << "block Backward RST" << endl;

    free(ptr);
    return true;
}



int main(int argc, char* argv[]) {

    
    if(argc != 3) {
        usage();
        return false; 
    }
    
    char* dev = argv[1];
    char* pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    initMyIpMac(dev);
    
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
            
        if (res == PCAP_ERROR_BREAK || res == PCAP_ERROR)
        {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return -1;
        }

        EthHdr* ethHdr = (EthHdr*)packet;
        if(ethHdr->type() != ethHdr->Ip4) continue;

        IpHdr* ipHdr = (IpHdr*) (packet+14);
        if(ipHdr->protocol != 0x6) continue;
		TcpHdr* tcpHdr = (TcpHdr*) ((size_t)ipHdr + (ipHdr->header_length<<2));

        int tcpLength = header->len - ((size_t)tcpHdr + (tcpHdr->doff<<2)) + (size_t)packet;
        if(tcpLength == 0) continue;
        const char* tcpPayload = (const char*) ((size_t)tcpHdr + (tcpHdr->doff<<2));


        //1. http
        if(tcpHdr->src() == 80 || tcpHdr->dst() == 80) {
            // find pattern using STL
            if(search(tcpPayload, tcpPayload + tcpLength, pattern, pattern + strlen(pattern)) == tcpPayload + tcpLength) continue; // no match
            if(!sendBF(handle, *ethHdr, *ipHdr, *tcpHdr, (unsigned char*)blockSite, strlen(blockSite)+1, 0x01 + 0x10)) break;
            if(!sendF(handle, *ethHdr, *ipHdr, *tcpHdr, NULL, NULL, 0x04 + 0x10)) break;
        } 

        //2. https
        else if(tcpHdr->src() == 443 || tcpHdr->dst() == 443) {
            if(search(tcpPayload, tcpPayload + tcpLength, pattern, pattern + strlen(pattern)) == tcpPayload + tcpLength) continue; // no match
            if(!sendBR(handle, *ethHdr, *ipHdr, *tcpHdr, NULL, NULL, 0x04 + 0x10)) break;
            if(!sendF(handle, *ethHdr, *ipHdr, *tcpHdr, NULL, NULL, 0x04 + 0x10)) break;
        }
    }
}