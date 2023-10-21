#pragma once

#include <cstdint>
#include "mac.h"

//refer. radiotap.org
#pragma pack(push, 1)
typedef struct Radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}rf;
#pragma pack(pop)

#pragma pack(push, 1)

typedef struct Deauth_frame {
    uint8_t type; // version:2 type:2 subtype:4
    uint8_t flags;
    uint16_t duration;
    
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t frag_seq;

    uint16_t reason;
}df;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct Deauth_packet {
    rf radio;
    df deauth;

    void init() {
        this->radio.it_version = 0;
        this->radio.it_pad = 0;
        this->radio.it_len= 0;
        this->radio.it_present = 0;

        this->deauth.type = 0xc0; // version:2 = 0, type:2 = 0, subtype:4 = 0xc
        this->deauth.flags = 0;
        this->deauth.duration = 0;
        this->deauth.frag_seq = 0;
        this->deauth.reason = 0x0007; // htons(0x0700)
    }

    void setPacket(Mac idest, Mac isource, Mac ibssid)
    {
        this->deauth.dest = idest;
        this->deauth.source = isource;
        this->deauth.bssid = ibssid;
    }

}dp;
#pragma pack(pop)

