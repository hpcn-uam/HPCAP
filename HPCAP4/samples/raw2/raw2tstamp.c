#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>

#include "../../include/hpcap.h"
#include "raw2.h"

int main(int argc, char **argv)
{
	FILE *fraw,*fout;
	u_char buf[4096];
	u_int32_t secs,nsecs;
	u_int64_t tstamp;
	u_int64_t epoch=0;
	u_int16_t len,caplen;
	int i=0,j=0,ret=0;
	char filename[100];

	if( argc != 3 )
	{
		printf("Uso: %s <fichero_RAW_de_entrada> <fichero_PCAP_de_salida>\n", argv[0]);
		exit(-1);
	}


	fraw=fopen(argv[1],"r");
	if( !fraw )
	{
		perror("fopen");
		exit(-1);
	}
	fout=fopen(argv[2],"w");
	if( !fout )
	{
		perror("fopen");
		fclose(fout);
		exit(-1);
	}
	
	i=0;
	while(1)
	{

			/* Lectura de info asociada a cada paquete */
			if( fread(&secs,1,sizeof(u_int32_t),fraw)!=sizeof(u_int32_t) )
			{
				printf("Segundos\n");
				break;
			}
			if( fread(&nsecs,1,sizeof(u_int32_t),fraw)!=sizeof(u_int32_t) )
			{
				printf("Nanosegundos\n");
				break;
			}
			if( nsecs >= NSECS_PER_SEC )
			{
				printf("Wrong NS value (file=%d,pkt=%d)\n",j,i);
				//break;
			}
			if( (secs==0) && (nsecs==0) )
			{
				fread(&caplen,1,sizeof(u_int16_t),fraw);
				fread(&len,1,sizeof(u_int16_t),fraw);
				if( len != caplen )
					printf("Wrong padding format [len=%d,caplen=%d]\n", len, caplen);
				else
					printf("Padding de %d bytes\n", caplen);
				break;
			}
			if( epoch == 0 )
				epoch = secs;
			
			if( fread(&caplen,1,sizeof(u_int16_t),fraw)!=sizeof(u_int16_t) )
			{
				printf("Caplen\n");
				break;
			}
			if( fread(&len,1,sizeof(u_int16_t),fraw)!=sizeof(u_int16_t) )
			{
				printf("Longitud\n");
				break;
			}
			

			/* Escritura de cabecera */
			tstamp = secs-epoch;
			tstamp *= 1000000000ul;
			tstamp += nsecs;
	
			/* Lectura del paquete */
			if( len > 0 )
			{
				ret = fread(buf,1,len,fraw);
				if( ret != len )
				{
					printf("Lectura del paquete\n");
					break;
				}
				/*for(j=0;j<64;j+=8)
				{
					printf( "\t%02x %02x %02x %02x\t%02x %02x %02x %02x\n", buf[j], buf[j+1], buf[j+2], buf[j+3], buf[j+4], buf[j+5], buf[j+6], buf[j+7]);
				}*/
	
			}
			/* Escribir a fichero */
			fprintf( fout, "%lu\t%d\t%d\n", tstamp, len, caplen);
			i++;

			#ifdef PKT_LIMIT
				if( i >= PKT_LIMIT )
					break;
			#endif
	}
	printf("%d paquetes leidos\n",i);
	fclose(fout);
	fclose(fraw);

	return 0;
}
