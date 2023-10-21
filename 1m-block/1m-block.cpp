#include <bits/stdc++.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include "ip.h"
#include <sqlite3.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


char* dbname;

struct IpHdr final {
    uint8_t header_length:4;
	uint8_t version:4;
    uint8_t tos;

    uint16_t total_length;
    uint16_t identification;
    
    uint8_t flags:3;
    uint16_t fragment_offset:13;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    
    Ip sip;
    Ip dip;
};

struct TcpHdr final { // grabber.h

	__u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

// ref http://www.devkuma.com/books/pages/1332#google_vignette
// ref http://wiki.pchero21.com/wiki/Libsqlite3
bool ck_db(char* hostadr) 
{
	sqlite3* db;
	sqlite3_stmt* res;

	int rc = sqlite3_open(dbname, &db);
	int rc2;
	if(rc != SQLITE_OK){
		 fprintf(stderr, "db open error\n");
		 sqlite3_close(db);
		 goto FALSE;
	}

	rc = sqlite3_prepare_v2(db, "SELECT * FROM urls WHERE url LIKE ?;", -1, &res, 0);
	if(rc != SQLITE_OK){
		 fprintf(stderr, "db query error\n");
		 sqlite3_close(db);
		 goto FALSE;
	} else sqlite3_bind_text(res, 1, hostadr, strlen(hostadr), SQLITE_STATIC);

	rc2 = sqlite3_step(res);
	if(rc2 == SQLITE_ROW){ // url exist
		printf("exist!\n%d : [%s]\n", sqlite3_column_int(res, 0), sqlite3_column_text(res, 1));
		goto TRUE;
	} else goto FALSE;

	//terminate
	sqlite3_finalize(res);
	sqlite3_close(db);
	
	FALSE:
	return false;
	TRUE:
	return true;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *dup)
{

	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data, *pl;
	bool ck = true;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	ret = nfq_get_payload(nfa, &data);
	if (ret >= 0) { // 잘 들어왔냐?
		//printf("payload_len=%d\n", ret);

		IpHdr* ipHdr = (IpHdr*) data;
		//printf("protocol check?\t\t");
		if(ipHdr->protocol != 0x6) goto RET; // no TCP!
		int tlen = ntohs(ipHdr->total_length);
		int iplen = ipHdr->header_length*4;
		TcpHdr* tcpHdr = (TcpHdr*) (data + iplen);
		
		//printf("clear1\nport 80 check?\t\t");
		int src = ntohs(tcpHdr->source);
		int dst = ntohs(tcpHdr->dest);
		if(src != 80 && dst != 80) goto RET; // neither port is 80!
		
		//printf("clear2\nhttp check?\t\t");
		if(tlen - iplen == (tcpHdr->doff)*4) goto RET; // no other info!
		printf(".");
		unsigned char* httpHdr = data + iplen + (tcpHdr->doff)*4;

		const char* http_method[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
		///https://developer.mozilla.org/ko/docs/Web/HTTP/Methods

		char* slicePkt = strtok((char*)httpHdr, "\r\n");
		
		//printf("clear3\nmethod check?\t\t");
		for(auto iter:http_method){
			if(strncmp(slicePkt, iter, sizeof(iter)) == 0) goto RET;// is http method!
		}

		slicePkt = strtok(NULL, "\r\n");
		//printf("clear4\naddress check : [%s]\n", slicePkt);
		if(slicePkt == NULL) goto RET; // next slice not exist!

		//if(strstr(slicePkt, host) == NULL) goto RET; // no host adr! => now remove

		printf("corrent adr : [%s]\n", &slicePkt[6]);
		if(!ck_db(&slicePkt[6])) {
			printf("[%s] not blocked!\n", &slicePkt[6]);
			goto RET;
		}
		else printf("[%s] blocked!\n", &slicePkt[6]); //except host : 

    }
	ck = false;

	RET:
	return nfq_set_verdict(qh, id, ck ? NF_ACCEPT : NF_DROP, 0, NULL);

}

void usage()
{
	printf("syntax : sudo netfilter-test <host>\nsample : sudo netfilter-test test.gilgil.net\n");
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    if(argc != 2){
        usage();
        return -1;
    }

	dbname = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("\npkt received ");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}