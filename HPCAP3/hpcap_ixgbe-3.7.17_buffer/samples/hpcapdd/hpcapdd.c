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

unsigned int process_block(struct hpcap_handle *,int fd, u_int32_t remain);

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
	if( argc != 4 )
	{
		//printf("Uso: %s <adapter index> <queue index> <fichero RAW de salida> <bs> <count>\n", argv[0]);
		printf("Uso: %s <adapter index> <queue index> <output basedir>\n", argv[0]);
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
	/* Map device's memory */
	ret = hpcap_map(&hp);
	if( ret != HPCAP_OK )
	{
		printf("Error when opening the mapping HPCAP memory\n");
		hpcap_close( &hp );
		close(fd);
		return HPCAP_ERR;
	}

	signal(SIGINT, capturaSenial);

	int first=1;	

	while( !stop )
	{
		#ifdef OWRITE
		gettimeofday(&initwr, NULL);
		sprintf(filename, "%s/%d", argv[3], ((int)initwr.tv_sec/DIRFREQ)*DIRFREQ);//a directory created every 1/2 hour
		mkdir(filename, S_IWUSR);//if the dir already exists, it returns -1
		//printf("filename:%s\n",filename);
		sprintf(filename, "%s/%d/%d_xge%d_%d.raw", argv[3],((int)initwr.tv_sec/DIRFREQ)*DIRFREQ,(int)initwr.tv_sec, ifindex,qindex);
		/* Opening output file */
		fd = open(filename, O_RDWR | O_TRUNC | O_CREAT /*| O_DIRECT | O_LARGEFILE*/, 00666);
		printf("filename:%s\n",filename);
		if( fd == -1 )
		{
			printf("Error when opening output file\n");
			return HPCAP_ERR;
		}
		#endif
		

		i=0;
		acks = 0;
		while( i < BS*COUNT )
		{
			/* acumular para escribir un bloque */
			hpcap_ack_wait_timeout( &hp, acks, /*BS*/1, -1);
			acks = process_block(&hp,fd, (BS*COUNT)-i);
			i += acks;
		}
		hpcap_ack( &hp, acks);
		//gettimeofday(&endwr, NULL);
	
		#ifdef OWRITE
		close(fd);
		#endif
		/*wrtime = endwr.tv_sec - initwr.tv_sec;
		wrtime += (endwr.tv_usec - initwr.tv_usec)*1e-6;

		printf("[%s]\n",filename);
		printf("Transfer time: %lf s (%d transfers)\n", wrtime, i);
		printf("\t%lu Mbytes transfered => %lf MBps\n", COUNT*BS/MEGA, (1.0*count*BS/MEGA) / wrtime );*/
	}
	
	/*gettimeofday(&end, NULL);
	time = end.tv_sec - init.tv_sec;
	time += (end.tv_usec - init.tv_usec)*1e-6;
	printf("Total time: %lfs\n", time );*/
	
	hpcap_unmap(&hp);
	hpcap_close(&hp);
	
	return 0;
}


unsigned int process_block(struct hpcap_handle * hp,int fd, u_int32_t remain)
{
	u_int32_t aux;
	unsigned int ready = minimo(remain, hp->avail);
	
	#ifdef OWRITE
		/* escribir bloque a bloque */
		if( (hp->rdoff + ready ) > HPCAP_BUF_SIZE )
		{
			aux = HPCAP_BUF_SIZE - hp->rdoff;
			/* hay que hacerlo en dos transferencias */
			write( fd, &hp->buf[ hp->rdoff ], aux);
			write( fd, hp->buf, ready-aux);
		}
		else
		{	/* se hace en una transferencia */
			write( fd, &hp->buf[ hp->rdoff ], ready);
		}
	#else
	#endif
	
	return ready;
}

