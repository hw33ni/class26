#pragma once

#include "iphdr.h"

#pragma pack(push, 1)

struct TcpHdr final { // grabber.h

	uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t res1:4, doff:4;
    uint8_t flags;
    //fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    uint16_t src() { return ntohs(source); }
    uint16_t dst() { return ntohs(dest); }
    uint16_t sum() { return ntohs(checksum); }

	enum: uint8_t {
		Urg = 0x20,
		Ack = 0x10,
		Psh = 0x08,
		Rst = 0x04,
		Syn = 0x02,
		Fin = 0x01
	};


    void init(
        uint16_t isource,
        uint16_t idest,
        uint32_t iseq,
        uint32_t iack_seq,
        uint8_t idoff,
        uint8_t iflags,
        uint16_t ichecksum
    )
    {
        this->source = isource;
        this->dest = idest;
        this->seq = iseq;
        this->ack_seq = iack_seq;
        this->doff= idoff;
        this->flags = iflags;
        this->checksum = ichecksum;
    };

    static uint16_t calcChecksum(IpHdr* ipHdr, TcpHdr* tcpHdr);
};
#pragma pack(pop)