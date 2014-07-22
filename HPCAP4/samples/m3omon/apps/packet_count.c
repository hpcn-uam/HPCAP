#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include "../lib/libmgmon.h"

u_int64_t pkts,bytes;
u_int32_t last_sec=0;

void packet_count(u_int8_t *payload, struct pcap_pkthdr *header, void *arg)
{
	if( header->ts.tv_sec != last_sec )
	{
		printf("%lu\t%lu\n", pkts, 8*bytes);
		pkts = 0;
		bytes = 0;
		last_sec = header->ts.tv_sec;
	}
	pkts++;
	bytes += header->len;
}

int main( int argc, char *argv[])
{
	int core;
	
	if( argc != 2 )
	{
		printf("Usage: %s <core>\n", argv[0]);
		return -1;
	}
	core = atoi(argv[1]);
		
	mgmon_packet_online_loop(core, 1, 0, packet_count, NULL);
	
	return 0;
}
