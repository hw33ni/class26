#pragma once
#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include "libnet.h"
#include <stdint.h>

typedef struct libnet_ethernet_hdr hdr1;
typedef struct libnet_ipv4_hdr hdr2;
typedef struct libnet_tcp_hdr hdr3;

typedef uint8_t u8;
typedef uint16_t u16;

void p_mac(u8* mac);
void p_ip(u8* ip);
void p_port(u16 port);

