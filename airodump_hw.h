#pragma once

#include <cstdint>
#include "mac.h"

//refer. radiotap.org
#pragma pack(push, 1)
typedef struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}rf;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct Beacon_frame {
    uint8_t type; // version:2 type:2 subtype:4
    uint8_t flags;
    uint16_t duration;
    
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t frag_seq;
}bf;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct fixed_frame {
    uint64_t timestamp;
    uint16_t interval;
    uint16_t cap;
}ff;

#pragma pack(pop)
typedef struct tagged_frame {
    uint8_t num;
    uint8_t len;
    char essid;
}tf;