#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include "../lib/libmgmon.h"

void mrtg_show(mrtg *stat, void *arg)
{
	printf("bits: %lu, pkts: %lu, flows: %lu\n", 8*stat->bytes, stat->packets, stat->concurrent_flows);
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
		
	mgmon_mrtg_online_loop(core, 1, 0, mrtg_show, NULL);
	
	return 0;
}
