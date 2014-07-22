#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include "../lib/libmgmon.h"

u_int64_t flows;
u_int64_t last_timestamp=0;

void flow_count(IPFlow * record, void *arg)
{
	if( record->lastpacket_timestamp != last_timestamp )
	{
		printf("%lu\n", flows);
		flows = 0;
		last_timestamp = record->lastpacket_timestamp;
	}
	flows++;
	printf("\t%lu\n", flows);
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
		
	mgmon_flow_online_loop(core, 1, 0, flow_count, NULL);
	
	return 0;
}
