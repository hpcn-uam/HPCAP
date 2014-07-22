#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>

#include "../../include/hpcap.h"


int main(int argc, char **argv)
{
	struct hpcap_handle hp;
	int ret=0;
	long int i=0;
	int ifindex=0,qindex=0;

	if( argc != 5 )
	{
		//printf("Uso: %s <adapter index> <queue index> <fichero RAW de salida> <bs> <count>\n", argv[0]);
		printf("Uso: %s <adapter index> <queue index> <begin buf> <end buf>\n", argv[0]);
		return HPCAP_ERR;
	}
	printf("HPCAP_BUF_SIZE:%lu\n",HPCAP_BUF_SIZE);

	/* Creating HPCAP handle */
	ifindex=atoi(argv[1]);
	qindex=atoi(argv[2]);
	ret = hpcap_open(&hp, ifindex, qindex);
	if( ret != HPCAP_OK )
	{
		printf("Error when opening the HPCAP handle\n");
		return HPCAP_ERR;
	}
	/* Map device's memory */
	ret = hpcap_map(&hp);
	if( ret != HPCAP_OK )
	{
		printf("Error when opening the mapping HPCAP memory\n");
		hpcap_close( &hp );
		return HPCAP_ERR;
	}

	hpcap_ack_wait_timeout(&hp, 0, atoi(argv[4]), 1000000000);
	printf("hp.avail:%d hp.rdoff:%u\n",hp.avail,hp.rdoff);
	for(i=atoi(argv[3]);i<atoi(argv[4]);i++){
		if(i%80==0)
			printf("\n%lu\t",i);
		if(i%4==0)
			printf(" ");
		printf("%02X",(u_char)hp.buf[i]);
	}
	printf("\n");
	hpcap_unmap(&hp);
	hpcap_close(&hp);
	return 0;
}
