#ifndef _MGMON_LIB_
#define _MGMON_LIB_

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MCAST_BASE 224
#define MCAST_FLOW 128
#define MCAST_MRTG 129

#define MCAST_PORT 1500
//#define MCAST_PORT 65535
#define MCAST_TTL 1

#define BIND_IFACE_IP "127.0.0.1"

typedef struct {
	sigset_t signal_mask;
	int stop;
}mgmon_signal;

#define MAX_PACK 10
#define MAX_PAYLOAD 400

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
	double avg_pack_size,std_pack_size;//new
	
	u_int64_t previous_timestamp;
	
	u_int64_t rtt_syn; 
	u_int8_t rtt_syn_done;
	
	double max_int_time;
	double min_int_time;
	double sum_int_time;
	double sum_int_time_sqr;
	double avg_int_time,std_int_time;//new

	u_int64_t lastpacket_timestamp;//new
	u_int64_t firstpacket_timestamp;//new
	u_int64_t duration;//new
	
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
}IPFlow;

typedef struct {
	u_int64_t bytes;
	u_int64_t packets;
	u_int64_t concurrent_flows;
	u_int64_t timestamp;
}mrtg;

typedef void (*packet_handler)(u_int8_t *payload, struct pcap_pkthdr *header, void *arg);
typedef void (*flow_handler)(IPFlow *record, void *arg);
typedef void (*mrtg_handler)(mrtg *stat, void *arg);


int mgmon_packet_online_loop(int cpu, int ifindex, int qindex, packet_handler callback, void *arg);
int mgmon_flow_online_loop(int cpu, int ifindex, int qindex, flow_handler callback, void *arg);
int mgmon_mrtg_online_loop(int cpu, int ifindex, int qindex, mrtg_handler callback, void *arg);

int open_multicast_tx_socket(int mode, int ifindex, int qindex, struct sockaddr_in *dstAddr);

#endif /* _MGMON_LIB_ */
