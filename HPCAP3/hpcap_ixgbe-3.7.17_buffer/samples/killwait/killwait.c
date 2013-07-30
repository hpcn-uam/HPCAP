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

#define MEGA (1024*1024)
//#define OWRITE
#define DIRFREQ 1800

#define BS (HPCAP_BS)
#define COUNT (HPCAP_COUNT)

/*
 Función que se ejecuta cuando se genera la señal generada por Control+C. La idea es 
 realizar una salida "ordenada".
 Parametros de entrada:
	-int nSenial: identificador de la señal capturada.
*/
int stop=0;
void capturaSenial(int nSenial)
{
	if(stop==1)
		return;
	stop=1;
	return;
}


int main(int argc, char **argv)
{
	int fd=0;
	struct hpcap_handle hp;
	int ret=0;
	unsigned long int i=0, aux=0;
	int ifindex=0,qindex=0;
	unsigned long acks=0;

	//struct timeval init, end;
	struct timeval initwr, endwr;
	//float time,wrtime;

	char filename[512];
	

	//gettimeofday(&init, NULL);
	if( argc != 3 )
	{
		//printf("Uso: %s <adapter index> <queue index> <fichero RAW de salida> <bs> <count>\n", argv[0]);
		printf("Uso: %s <adapter index> <queue index>\n", argv[0]);
		return HPCAP_ERR;
	}
		
	/* Creating HPCAP handle */
	ifindex=atoi(argv[1]);
	qindex=atoi(argv[2]);
	ret = hpcap_open(&hp, ifindex, qindex);
	if( ret != HPCAP_OK )
	{
		printf("Error when opening the HPCAP handle\n");
		close(fd);
		return HPCAP_ERR;
	}
	
	hpcap_ioc_killwait(&hp);
	
	hpcap_close(&hp);
	
	return 0;
}

