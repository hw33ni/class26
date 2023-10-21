#pragma once

#include "ip.h"
#include <cstring>
#include <arpa/inet.h>


#pragma pack(push, 1)

struct IpHdr  {
    uint8_t header_length:4,
            version:4;
    uint8_t tos;

    uint16_t total_length;
    uint16_t identification;
    
    uint16_t flag_offset;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    
    Ip sip_;
    Ip dip_;

    uint16_t len() { return ntohs(total_length); }
	Ip sip() { return ntohl(sip_); }
	Ip dip() { return ntohl(dip_); }

    void init(  
        uint8_t iheader_length,
        uint16_t itotal_length,
        uint16_t iflag_offset,
        uint8_t ittl,
        Ip isip,
        Ip idip)
    {
        this->header_length = iheader_length;
        this->total_length = itotal_length;
        this->flag_offset = iflag_offset;
        this->ttl = ittl;
        this->sip_ = isip;
        this->dip_ = idip;

        uint32_t sum = 0;
        uint16_t *adr = (uint16_t*)this;
        uint16_t count = this->header_length<<2;
        while(count > 1){
            sum += *adr++;
            count -= 2;
        }
        if(count == 1) sum += ((*adr)&htons(0xff00));
        while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        this->checksum = ~(uint16_t)sum;
    };

    
};

#pragma pack(pop)