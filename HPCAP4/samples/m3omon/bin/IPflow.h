#ifndef __IPflow_H__
#define __IPflow_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <math.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include "list.h"
#include "../lib/libmgmon.h"
#define MAX_FLOWS_TABLE_SIZE 16777216
//16777216 2^24 134217728 2^27
#define EXPIRATION_FLOW_TIME 30*1000000
#define MAX_FRAG_PACKETS_TABLE_SIZE 65536
#define MAX_PACK 10
#define MAX_PAYLOAD 400

#define ETH_HLEN 14
#define IP_HLEN_MIN 20
#define IP_SIP 12
#define IP_DIP 16
#define IP_ALEN 4
#define ETH_ALEN 6
#define IP_PROTO 9
#define ICMP_PROTO 1
#define TCP_PROTO 6
#define UDP_PROTO 17
#define UDP_HLEN 8
#define ICMP_HLEN 8

#if 0
typedef struct IPFlow
{
	u_int32_t source_ip;
	u_int32_t destination_ip;
	u_int64_t source_mac;
	u_int64_t destination_mac;
	u_int16_t source_port;
	u_int16_t destination_port;
	u_int8_t transport_protocol;


	u_int64_t nbytes;
	u_int32_t npack;

	u_int16_t max_pack_size;
	u_int16_t min_pack_size;
	u_int64_t nbytes_sqr;

	u_int64_t previous_timestamp;

	u_int64_t rtt_syn;
	u_int8_t rtt_syn_done;

	double max_int_time;
	double min_int_time;
	double sum_int_time;
	double sum_int_time_sqr;

	u_int32_t num_flags[8];
	// 0 FIN;
	// 1 SYN;
	// 2 RST;
	// 3 PSH;
	// 4 ACK;
	// 5 URG;
	// 6 CWR;
	// 7 ECE;
	u_int32_t nwindow_zero;

	u_int8_t *payload_ptr;

	u_int32_t npack_payload;
	u_int32_t current_seq_number;
	u_int32_t previous_seq_number;

	u_int16_t dataLen;
	u_int16_t offset;


	u_int8_t flags;
	u_int8_t flag_FIN;
	u_int8_t flag_ACK_nulo;

	// Frag packets flag
	u_int8_t frag_flag;
	u_int16_t ip_id;

	u_int8_t expired_by_flags;
	
	u_int64_t timestamp[MAX_PACK];
	u_int16_t packet_offset[MAX_PACK];
	u_int16_t size[MAX_PACK];
	u_int8_t payload[MAX_PAYLOAD];

} IPFlow;
#endif

typedef struct IPSession
{
	IPFlow *actual_flow;
	u_int64_t exportation_timestamp;
	u_int64_t lastpacket_timestamp;
	u_int64_t firstpacket_timestamp;
	node_l *active_node;
	u_int64_t network_membership_IN; //sólo puede pertenecer a 64 redes
        u_int64_t network_membership_OUT;//sólo puede pertenece a 64 redes
	IPFlow incoming;
	IPFlow outgoing;

}IPSession;

typedef void (*fp_export_session) (IPSession * flow);
u_int32_t getIndex (IPFlow * flow);
IPSession *insertFlow (IPSession* aux_session);
void printTupleFilePayloadText (IPSession *session,FILE* f);
void printTupleFileTextAndBin (IPSession *session,FILE* f_txt,FILE *f_bin,u_int64_t *offset_bin);
void printTupleFilePayloadBin (IPSession *session,FILE* f);
void cleanup_flows ();
IPSession* getIPSession(void);
void releaseIPSession(IPSession* f);
void allocIPSessionPool(void);
void freeIPSessionPool(void);
void processFlow(u_int8_t *bp,struct pcap_pkthdr *h,u_int64_t network_membership_IN,u_int64_t network_membership_OUT,u_int8_t num_tags);
/*void printTuple (IP_flow *flow);
void printTupleFile (IP_flow *flow,FILE* f);
int compare_tuple(void *a, void *b);
void initialize_IP_flow(IP_flow *flow);
IP_flow* remove_flow (node_l * current_node);
*/

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//MODIFICACION HECHA PARA GESTION DE FRAGMENTOS
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
IPFlow * getPointer_frag(u_int32_t ip_src,u_int32_t ip_dst,u_int8_t proto,u_int16_t ip_id);
void insertPointer_frag(IPFlow *  flow);
void removePointer_frag(IPFlow * flow);
int compFragPackets(void * a, void * b);

#endif
