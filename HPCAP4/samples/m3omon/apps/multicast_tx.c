#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../lib/libmgmon.h"

int main( int argc, char *argv[])
{
	int mode;
	struct sockaddr_in dstAddr;
	int sock;
	int stop=0;
	int __attribute__((unused)) ret;
	mrtg stat;
	IPFlow record;
	
	if( argc != 2 )
	{
		printf("Usage: %s <mode (0=flow, 1=MRTG)>\n", argv[0]);
		return -1;
	}
	mode = atoi(argv[1]);
	if( mode == 0 )
		mode = MCAST_FLOW;
	else if( mode == 1 )
		mode = MCAST_MRTG;
	else
		printf("Invalid mode\n");
		
	sock = open_multicast_tx_socket(mode, 1, 0, &dstAddr);
	
	stat.bytes = 0;
	stat.packets = 0;
	stat.concurrent_flows = 0;
	while( !stop )
	{
		if( mode == MCAST_FLOW )
		{
			struct timeval time;
			record.lastpacket_timestamp = time.tv_sec*1000000000+time.tv_usec*1000;
			ret = sendto(sock, &record, sizeof(record), 0, (struct sockaddr *)&dstAddr, sizeof(dstAddr));
			usleep(10);
		}
		else
		{
			stat.bytes++;
			stat.packets++;
			stat.concurrent_flows++;
			ret = sendto(sock, (void *)&stat, sizeof(mrtg), 0, (struct sockaddr *)&dstAddr, sizeof(dstAddr));
			sleep(1);
		}
	}
	
	return 0;
}
